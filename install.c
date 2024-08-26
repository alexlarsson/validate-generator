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

#include <fcntl.h>
#include <unistd.h>

typedef struct
{
  gboolean recursive;
  gboolean force;
  char *path_relative;
  char *path_prefix;
  GList *public_keys;
} InstallOptions;

static gboolean
replace_file (const char *destination_file, int content_fd, GError **error)
{
  g_debug ("   Replacing file: %s", destination_file);
  g_autofree gchar *destination_file_tmp = g_strdup_printf ("%s.XXXXXX", destination_file);

  errno = 0;
  autofd int tmp_fd = g_mkstemp_full (destination_file_tmp, O_RDWR, 0644);
  if (tmp_fd == -1)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno),
                   "Can't open tempfile for '%s': %s\n", destination_file, strerror (errno));
      return FALSE;
    }

  int res = copy_fd (content_fd, tmp_fd);
  if (res < 0)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno),
                   "Can't write to '%s': %s\n", destination_file_tmp, strerror (errno));
      (void)unlink (destination_file_tmp);
      return FALSE;
    }

  res = rename (destination_file_tmp, destination_file);
  if (res < 0)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Can't create '%s': %s\n",
                   destination_file, strerror (errno));
      (void)unlink (destination_file_tmp);
      return FALSE;
    }

  return TRUE;
}

static gboolean
install (InstallOptions *opt, const char *path, const char *relative_to,
         const char *destination_dir, gboolean toplevel)
{
  struct stat st;
  gboolean success = TRUE;
  g_debug ("Installing %s", path);

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
      autofd int content_fd = -1;
      if (!load_file_data_for_sign (path, &st, NULL, &content, &content_len, &content_fd, &error))
        {
          g_printerr ("Failed to load '%s': %s\n", path, error->message);
          return FALSE;
        }

      g_autofree char *rel_path = opt_get_relative_path (path, relative_to, opt->path_prefix);
      if (rel_path == NULL)
        {
          g_printerr ("File '%s' not inside relative dir\n", path);
          return FALSE;
        }

      g_autoptr (GError) validate_error = NULL;
      if (!validate_data (rel_path, type, content, content_len, signature, signature_len,
                          opt->public_keys, &validate_error))
        {
          if (validate_error)
            g_printerr ("Signature of '%s' (as '%s') is invalid: %s\n", path, rel_path,
                        validate_error->message);
          else
            g_printerr ("Signature of '%s' (as '%s') is invalid\n", path, rel_path);
          return FALSE;
        }

      g_autofree char *basename = g_path_get_basename (path);
      g_autofree char *destination_file = g_build_filename (destination_dir, basename, NULL);

      if (!opt->force && g_file_test (destination_file, G_FILE_TEST_EXISTS))
        {
          g_info ("File '%s' already exist, ignoring", destination_file);
          return TRUE;
        }

      if (g_mkdir_with_parents (destination_dir, 0755) < 0)
        {
          g_printerr ("Unable to create dir '%s': %s", destination_file, strerror (errno));
          return FALSE;
        }

      if (type == S_IFLNK)
        {
          res = unlink (destination_file);
          if (res < 0 && errno != ENOENT)
            {
              g_printerr ("Can't remove old symlink '%s': %s\n", destination_file,
                          strerror (errno));
              return FALSE;
            }
          res = symlink ((char *)content, destination_file);
          if (res < 0)
            {
              g_printerr ("Can't create symlink '%s': %s\n", destination_file, strerror (errno));
              return FALSE;
            }
        }
      else
        {
          g_assert (content_fd != -1);

          g_autoptr (GError) replace_error = NULL;
          if (!replace_file (destination_file, content_fd, &replace_error))
            {
              g_printerr ("%s\n", replace_error->message);
              return FALSE;
            }
        }

      g_info ("Installed file '%s'", destination_file);
    }
  else if (type == S_IFDIR)
    {
      /* NOTE: It is important that we don't actually create a target directory
       * here until we have a validated source file in this directory, because
       * otherwise that would allow the creation of arbitrary directory names
       * without validation. */

      g_autoptr (GError) dir_error = NULL;
      g_autoptr (GDir) dir = g_dir_open (path, 0, &dir_error);
      if (dir == NULL)
        {
          if (g_error_matches (dir_error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            return TRUE;

          g_printerr ("Failed to open dir '%s': %s\n", path, strerror (errno));
          return FALSE;
        }

      g_autofree char *basename = g_path_get_basename (path);
      g_autofree char *destination_subdir
          = g_build_filename (destination_dir, toplevel ? NULL : basename, NULL);

      const char *child;
      while ((child = g_dir_read_name (dir)) != NULL)
        {
          if (g_str_has_suffix (child, ".sig"))
            continue; /* Skip existing signatures */

          g_autofree char *child_path = g_build_filename (path, child, NULL);
          if (!install (opt, child_path, relative_to, destination_subdir, FALSE))
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

static gboolean
install_for_config (InstallOptions *opt, const char **sources, const char *destination)
{
  g_debug ("Entering install_for_config");
  gboolean res = TRUE;
  for (gsize i = 0; sources[i] != NULL; i++)
    {
      g_autofree char *path = g_canonicalize_filename (sources[i], NULL);
      g_debug ("   Working on: %s", path);

      if (g_file_test (path, G_FILE_TEST_IS_DIR))
        {
          g_debug ("   %s is a directory", path);
          if (!opt->recursive)
            {
              g_debug ("   No recursion set");
              g_printerr ("error: '%s' is a directory and not in recursive mode\n", path);
              return EXIT_FAILURE;
            }

          g_debug ("Installing from %s to %s", path, destination);
          if (!install (opt, path, opt->path_relative ? opt->path_relative : path, destination,
                        TRUE))
            res = FALSE;
        }
      else if (g_file_test (path, G_FILE_TEST_IS_REGULAR))
        {
          g_debug ("   %s is a file", path);
          g_autofree char *dirname = g_path_get_dirname (path);

          /* TODO: Handle opt->path_relative here?? */
          if (!install (opt, path, dirname, destination, TRUE))
            res = FALSE;
        }
      else
        {
          g_debug ("   %s is no supported", path);
          g_autoptr (GError) error = NULL;
          g_autoptr (GDir) dir = g_dir_open (path, 0, &error);
          if (dir == NULL)
            {

              if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
                {
                  g_debug ("%s not found - ignoring", path);
                }

              g_printerr ("Can't enumerate config dir %s: %s", path, error->message);
              res = FALSE;
              continue;
            }
        }
    }

  return res;
}

static void
get_install_options_from_cmdline (InstallOptions *opt)
{
  memset (opt, 0, sizeof (InstallOptions));

  opt->recursive = opt_recursive;
  opt->force = opt_force;
  opt->path_relative = opt_path_relative;
  opt->path_prefix = opt_path_prefix;
  opt->public_keys = opt_public_keys;
}

static void
free_install_options (InstallOptions *opt)
{
  g_free (opt->path_relative);
  g_free (opt->path_prefix);

  free_keys (opt->public_keys);
}

static gboolean
get_install_options_from_file (InstallOptions *opt, const char *config_path, char **destination_out,
                               char ***sources_out)
{
  g_debug ("Entering get_install_options_from_file");
  memset (opt, 0, sizeof (InstallOptions));

  g_autoptr (GKeyFile) config = g_key_file_new ();

  g_autoptr (GError) error = NULL;
  if (!g_key_file_load_from_file (config, config_path, G_KEY_FILE_NONE, &error))
    {
      /* Ignore non-existing config files */
      if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        return TRUE;

      g_printerr ("Can't load config file '%s': %s\n", config_path, error->message);
      return FALSE;
    }

  g_autofree char *destination = g_key_file_get_string (config, "install", "destination", &error);
  if (destination == NULL)
    {
      g_printerr ("Can't get destination from config file '%s': %s\n", config_path, error->message);
      return FALSE;
    }

  g_auto (GStrv) sources = g_key_file_get_string_list (config, "install", "sources", NULL, &error);
  if (sources == NULL)
    {
      g_printerr ("Can't get sources from config file '%s': %s\n", config_path, error->message);
      return FALSE;
    }

  /* Default for force and recursive is TRUE, as it is more common */

  if (!keyfile_get_boolean_with_default (config, "install", "recursive", TRUE, &opt->recursive,
                                         &error))
    {
      g_printerr ("Can't parse recursive option from config file '%s': %s\n", config_path,
                  error->message);
      return FALSE;
    }

  if (!keyfile_get_boolean_with_default (config, "install", "force", TRUE, &opt->force, &error))
    {
      g_printerr ("Can't parse force option from config file '%s': %s\n", config_path,
                  error->message);
      return FALSE;
    }

  g_autofree char *path_relative = NULL;
  if (!keyfile_get_value_with_default (config, "install", "path_relative", NULL, &path_relative,
                                       &error))
    {
      g_printerr ("Can't parse path_relative option from config file '%s': %s\n", config_path,
                  error->message);
      return FALSE;
    }

  g_autofree char *path_prefix = NULL;
  if (!keyfile_get_value_with_default (config, "install", "path_prefix", NULL, &path_prefix,
                                       &error))
    {
      g_printerr ("Can't parse path_prefix option from config file '%s': %s\n", config_path,
                  error->message);
      return FALSE;
    }

  g_auto (GStrv) keys = NULL;
  if (!keyfile_get_string_list_with_default (config, "install", "keys", ';', NULL, &keys, &error))
    {
      g_printerr ("Can't parse public_keys option from config file '%s': %s\n", config_path,
                  error->message);
      return FALSE;
    }

  g_auto (GStrv) key_dirs = NULL;
  if (!keyfile_get_string_list_with_default (config, "install", "key_dirs", ';', NULL, &key_dirs,
                                             &error))
    {
      g_printerr ("Can't parse public_keys option from config file '%s': %s\n", config_path,
                  error->message);
      return FALSE;
    }

  opt->public_keys = read_public_keys ((const char **)keys, (const char **)key_dirs);

  opt->path_relative = g_steal_pointer (&path_relative);
  opt->path_prefix = g_steal_pointer (&path_prefix);

  *destination_out = g_steal_pointer (&destination);
  *sources_out = g_steal_pointer (&sources);

  return TRUE;
}

int
cmd_install (int argc, char *argv[])
{
  gboolean res = TRUE;
  g_debug ("Entering cmd_install");

  if (argc > 1)
    {
      if (argc == 2)
        help_error ("No destination given");

      InstallOptions main_opt;
      get_install_options_from_cmdline (&main_opt);

      const char *destination = argv[argc - 1];

      g_autoptr (GPtrArray) sources = g_ptr_array_new ();
      for (gsize i = 1; i < argc - 1; i++)
        g_ptr_array_add (sources, argv[i]);
      g_ptr_array_add (sources, NULL);

      res &= install_for_config (&main_opt, (const char **)sources->pdata, destination);
    }

  for (gsize i = 0; opt_configs != NULL && opt_configs[i] != NULL; i++)
    {
      const char *config_file = opt_configs[i];

      g_info ("Loading config file %s", config_file);

      g_autofree char *destination = NULL;
      g_auto (GStrv) sources = NULL;
      InstallOptions opt;
      if (!get_install_options_from_file (&opt, config_file, &destination, &sources))
        {
          res = FALSE;
          continue;
        }

      if (destination)
        res &= install_for_config (&opt, (const char **)sources, destination);

      free_install_options (&opt);
    }

  for (gsize i = 0; opt_config_dirs != NULL && opt_config_dirs[i] != NULL; i++)
    {
      const char *config_dir = opt_config_dirs[i];
      g_info ("Loading config files from %s", config_dir);

      g_autoptr (GError) error = NULL;
      g_autoptr (GDir) dir = g_dir_open (config_dir, 0, &error);
      if (dir == NULL)
        {

          if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            {
              g_debug ("%s not found - ignoring", config_dir);
              continue;
            }

          g_printerr ("Can't enumerate config dir %s: %s", config_dir, error->message);
          res = FALSE;
          continue;
        }

      g_debug ("Entering %s to load the config files", config_dir);

      const char *filename;
      while ((filename = g_dir_read_name (dir)) != NULL)
        {
          g_autofree char *config_file = g_build_filename (config_dir, filename, NULL);

          g_info ("Loading config file %s", config_file);

          g_autofree char *destination = NULL;
          g_auto (GStrv) sources = NULL;
          InstallOptions opt;
          if (!get_install_options_from_file (&opt, config_file, &destination, &sources))
            {
              g_debug ("Could not find install options from file %s", config_file);
              res = FALSE;
              continue;
            }

          if (destination)
            res &= install_for_config (&opt, (const char **)sources, destination);

          free_install_options (&opt);
        }

      g_debug ("over & out");
    }

    g_debug ("over & out2");

  return res ? 0 : 1;
}
