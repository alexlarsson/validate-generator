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
validate (const char *path, const char *relative_to)
{
  struct stat st;
  gboolean success = TRUE;
  g_debug ("Validating %s", path);

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

      g_autofree char *signature = NULL;
      gsize signature_len = 0;

      g_autoptr (GError) error = NULL;
      if (!g_file_get_contents (sig_path, &signature, &signature_len, &error))
        {
          if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            g_printerr ("No signature for '%s'\n", path);
          else
            g_printerr ("Failed to load '%s': %s\n", sig_path, error->message);
          return FALSE;
        }

      g_autofree guchar *content = NULL;
      gsize content_len = 0;
      if (!load_file_data_for_sign (path, &st, NULL, &content, &content_len, NULL, &error))
        {
          g_printerr ("Failed to load '%s': %s\n", path, error->message);
          return FALSE;
        }

      g_autofree char *rel_path = opt_get_relative_path (path, relative_to, opt_path_prefix);
      if (rel_path == NULL)
        {
          g_printerr ("File '%s' not inside relative dir\n", path);
          return FALSE;
        }

      g_autoptr (GError) validate_error = NULL;
      if (!validate_data (rel_path, type, content, content_len, signature, signature_len,
                          opt_public_keys, &validate_error))
        {
          if (validate_error)
            g_printerr ("Signature of '%s' is invalid (as %s): %s\n", path, rel_path,
                        validate_error->message);
          else
            g_printerr ("Signature of '%s' is invalid (as %s)\n", path, rel_path);
          return FALSE;
        }

      g_info ("%s is valid (as %s)", path, rel_path);
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
          if (!validate (child_path, relative_to))
            success = FALSE;
        }
    }
  else
    {
      g_printerr ("Can't validate '%s' due to unsupported file type'\n", path);
      success = FALSE;
    }

  return success;
}

int
cmd_validate (int argc, char *argv[])
{
  g_autoptr (GError) error = NULL;
  g_debug ("Entering cmd_validate");

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

          if (!validate (path, opt_path_relative ? opt_path_relative : path))
            res = FALSE;
        }
      else
        {
          g_autofree char *dirname = g_path_get_dirname (path);

          if (!validate (path, opt_path_relative ? opt_path_relative : dirname))
            res = FALSE;
        }
    }

  return res ? EXIT_SUCCESS : EXIT_FAILURE;
}
