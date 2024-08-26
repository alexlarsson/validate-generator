/*
 * Copyright © 2023 Red Hat, Inc
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *       Alexander Larsson <alexl@redhat.com>
 */

#include "config.h"
#include "main.h"

static gboolean
sign (const char *path, const char *relative_to)
{
  struct stat st;
  gboolean success = TRUE;
  g_debug ("Signing %s", path);

  int res = lstat (path, &st);
  if (res < 0)
    {
      g_printerr ("Can't access '%s': %s\n", path, strerror (errno));
      return FALSE;
    }

  int type = st.st_mode & S_IFMT;
  if (type == S_IFREG || type == S_IFLNK)
    {
      g_autofree char *sig_path = g_strconcat (path, ".sig", NULL);

      if (!opt_force && g_file_test (sig_path, G_FILE_TEST_EXISTS))
        {
          g_info ("File '%s' already signed, ignoring", path);
          return TRUE; /* Already signed */
        }

      g_autofree guchar *content = NULL;
      gsize content_len = 0;

      g_autoptr (GError) error = NULL;
      if (!load_file_data_for_sign (path, &st, NULL, &content, &content_len, NULL, &error))
        {
          g_printerr ("Failed to read file '%s': %s\n", path, error->message);
          return FALSE;
        }

      g_autofree char *rel_path = opt_get_relative_path (path, relative_to, opt_path_prefix);
      if (rel_path == NULL)
        {
          g_printerr ("File '%s' not inside relative dir\n", path);
          return FALSE;
        }

      g_autofree guchar *signature = NULL;
      gsize signature_len = 0;

      if (!sign_data (type, rel_path, content, content_len, opt_private_key, &signature,
                      &signature_len, &error))
        {
          g_printerr ("Failed to sign file '%s': %s\n", path, error->message);
          return FALSE;
        }

      if (!g_file_set_contents (sig_path, (char *)signature, signature_len, &error))
        {
          g_printerr ("Failed to write file '%s': %s\n", sig_path, error->message);
          return FALSE;
        }

      g_info ("Wrote signature '%s' (for path %s)", sig_path, rel_path);
    }
  else if (type == S_IFDIR)
    {
      g_autoptr (GError) dir_error = NULL;
      g_autoptr (GDir) dir = g_dir_open (path, 0, &dir_error);
      if (dir == NULL)
        {
          if (g_error_matches (dir_error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            return TRUE;
          g_printerr ("Failed to open dir '%s': %s\n", path, strerror (errno));
          return FALSE;
        }

      const char *child;
      while ((child = g_dir_read_name (dir)) != NULL)
        {
          if (g_str_has_suffix (child, ".sig"))
            continue; /* Skip existing signatures */

          g_autofree char *child_path = g_build_filename (path, child, NULL);
          if (!sign (child_path, relative_to))
            success = FALSE;
        }
    }
  else
    {
      g_printerr ("Unsupported file type for '%s'\n", path);
      success = FALSE;
    }

  return success;
}

int
cmd_sign (int argc, char *argv[])
{
  g_autoptr (GError) error = NULL;
  g_debug ("Entering cmd_sign");

  if (argc == 1)
    help_error ("No input files given");

  gboolean res = TRUE;
  for (gsize i = 1; i < argc; i++)
    {
      g_autofree char *path = g_canonicalize_filename (argv[i], NULL);
      g_debug ("Checking %s", path);

      if (g_file_test (path, G_FILE_TEST_IS_DIR))
        {
          if (!opt_recursive)
            {
              g_printerr ("error: '%s' is a directory and not in recursive mode\n", path);
              return EXIT_FAILURE;
            }

          if (!sign (path, opt_path_relative ? opt_path_relative : path))
            res = FALSE;
        }
      else
        {
          g_autofree char *dirname = g_path_get_dirname (path);

          if (!sign (path, opt_path_relative ? opt_path_relative : dirname))
            res = FALSE;
        }
    }

  return res ? EXIT_SUCCESS : EXIT_FAILURE;
}
