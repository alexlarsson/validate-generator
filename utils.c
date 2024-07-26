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

#include <config.h>

#include "utils.h"

#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <unistd.h>

void
free_keys (GList *keys)
{
  for (GList *l = keys; l != NULL; l = l->next)
    EVP_PKEY_free (l->data);
  g_list_free (keys);
}

static const char *
get_ssl_error_reason (void)
{
  unsigned long e = ERR_get_error ();
  return ERR_reason_error_string (e);
}

static gboolean
fail_ssl_with_val_v (GError **error, int errval, const gchar *format, va_list args)
{
  g_autofree char *msg = g_strdup_vprintf (format, args);
  g_set_error (error, G_FILE_ERROR, errval, "%s: %s", msg, get_ssl_error_reason ());
  return FALSE;
}

static gboolean
fail_ssl_with_val (GError **error, int errval, const char *msg, ...)
{
  va_list args;

  va_start (args, msg);
  fail_ssl_with_val_v (error, errval, msg, args);
  va_end (args);

  return FALSE;
}

static gboolean
fail_ssl (GError **error, const char *msg, ...)
{
  va_list args;

  va_start (args, msg);
  fail_ssl_with_val_v (error, G_FILE_ERROR_FAILED, msg, args);
  va_end (args);

  return FALSE;
}

EVP_PKEY *
load_pub_key (const char *path, GError **error)
{
  g_autoptr (FILE) file = NULL;

  file = fopen (path, "rb");
  if (file == NULL)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Can't load key %s: %s",
                   path, strerror (errno));
      return NULL;
    }

  g_autoptr (EVP_PKEY) pkey = PEM_read_PUBKEY (file, NULL, NULL, NULL);
  if (pkey == NULL)
    {
      fail_ssl_with_val (error, G_FILE_ERROR_INVAL, "Can't parse public key %s", path);
      return NULL;
    }

  g_info ("Loaded public key '%s'", path);

  return g_steal_pointer (&pkey);
}

EVP_PKEY *
load_priv_key (const char *path, GError **error)
{
  g_autoptr (FILE) file = NULL;

  file = fopen (path, "rb");
  if (file == NULL)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Can't load key %s: %s",
                   path, strerror (errno));
      return NULL;
    }

  g_autoptr (EVP_PKEY) pkey = PEM_read_PrivateKey (file, NULL, NULL, NULL);
  if (pkey == NULL)
    {
      fail_ssl_with_val (error, G_FILE_ERROR_INVAL, "Can't parse private key %s", path);
      return NULL;
    }

  g_info ("Loaded private key '%s'", path);

  return g_steal_pointer (&pkey);
}

gboolean
load_pub_keys_from_dir (const char *key_dir, GList **out_keys, GError **error)
{
  GList *keys = NULL;

  g_autoptr (GError) my_error = NULL;
  g_autoptr (GDir) dir = g_dir_open (key_dir, 0, &my_error);
  if (dir == NULL)
    {
      if (g_error_matches (my_error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
        {
          *out_keys = NULL;
          return TRUE;
        }

      g_propagate_prefixed_error (error, my_error, "Can't enumerate key dir %s: ", key_dir);
      return FALSE;
    }

  const char *filename;
  while ((filename = g_dir_read_name (dir)) != NULL)
    {
      g_autofree char *path = g_build_filename (key_dir, filename, NULL);

      g_autoptr (EVP_PKEY) pkey = load_pub_key (path, &my_error);
      if (pkey == NULL)
        {
          if (!g_error_matches (my_error, G_FILE_ERROR, G_FILE_ERROR_NOENT)
              && !g_error_matches (my_error, G_FILE_ERROR, G_FILE_ERROR_ISDIR))
            {
              g_propagate_error (error, g_steal_pointer (&my_error));
              return FALSE;
            }
          g_clear_error (&my_error);
        }
      else
        {
          keys = g_list_prepend (keys, g_steal_pointer (&pkey));
        }
    }

  *out_keys = keys;
  return TRUE;
}

guchar *
make_sign_blob (const char *rel_path, int type, const guchar *content, gsize content_len,
                gsize *out_size, GError **error)
{
  gsize rel_path_len = strlen (rel_path);
  gsize to_sign_len = 1 + rel_path_len + 1 + content_len;
  g_autofree guchar *to_sign = g_malloc (to_sign_len);

  guchar *dst = to_sign;
  if (type == S_IFREG)
    *dst++ = 0;
  else if (type == S_IFLNK)
    *dst++ = 1;
  else
    {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_INVAL, "Unsupported file type");
      return NULL;
    }

  memcpy (dst, rel_path, rel_path_len);
  dst += rel_path_len;
  *dst++ = 0;
  memcpy (dst, content, content_len);
  dst += content_len;

  *out_size = to_sign_len;
  return g_steal_pointer (&to_sign);
}

gboolean
validate_data (const char *rel_path, int type, guchar *content, gsize content_len, char *sig,
               gsize sig_size, GList *pub_keys, GError **error)
{
  g_debug("Validating signature of: %s", rel_path);
  if (sig_size < VALIDATOR_SIGNATURE_MAGIC_LEN
      || memcmp (sig, VALIDATOR_SIGNATURE_MAGIC, VALIDATOR_SIGNATURE_MAGIC_LEN) != 0)
    {
      g_set_error (error, G_FILE_ERROR, G_FILE_ERROR_INVAL, "Invalid signature");
      g_debug("   Invalid signature size or value");
      return FALSE;
    }
  /* Skip past header */
  sig += VALIDATOR_SIGNATURE_MAGIC_LEN;
  sig_size -= VALIDATOR_SIGNATURE_MAGIC_LEN;

  gsize to_sign_len;
  g_autofree guchar *to_sign
      = make_sign_blob (rel_path, type, content, content_len, &to_sign_len, error);
  if (to_sign == NULL)
    {
      g_debug("   Nothing to sign");
      return FALSE;
    }

  gboolean valid = FALSE;
  for (GList *l = pub_keys; l != NULL; l = l->next)
    {
      EVP_PKEY *key = l->data;

      g_autoptr (EVP_MD_CTX) ctx = EVP_MD_CTX_new ();
      if (!ctx)
        return fail_ssl (error, "Can't init context");

      if (EVP_DigestVerifyInit (ctx, NULL, NULL, NULL, key) == 0)
        return fail_ssl (error, "Can't initialzie digest verify operation");

      int res = EVP_DigestVerify (ctx, (unsigned char *)sig, sig_size, (unsigned char *)to_sign,
                                  to_sign_len);
      g_debug("   Digest validation return code: %d", res);
      if (res == 1)
        {
          valid = TRUE;
          break;
        }
      else if (res != 0)
        return fail_ssl (error, "Error validating digest");
    }

  return valid;
}

static char *
sha512_file (const char *path, gsize *digest_len_out, int *fd_out, GError **error)
{
  autofd int fd = open (path, O_RDONLY);
  if (fd < 0)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Can't open %s: %s", path,
                   strerror (errno));
      return NULL;
    }

  g_autoptr (EVP_MD_CTX) ctx = EVP_MD_CTX_new ();
  if (!ctx)
    {
      fail_ssl (error, "Can't init context");
      return NULL;
    }

  if (EVP_DigestInit_ex (ctx, EVP_sha512 (), NULL) == 0)
    {
      fail_ssl (error, "Can't initialize sha512 operation");
      return NULL;
    }

  guchar buf[16 * 1024];
  while (TRUE)
    {
      ssize_t res = read (fd, buf, sizeof (buf));
      if (res < 0)
        {
          if (errno == EINTR)
            continue;
          g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Can't read %s: %s",
                       path, strerror (errno));
          return NULL;
        }
      else if (res == 0)
        break;

      if (EVP_DigestUpdate (ctx, buf, res) == 0)
        {
          fail_ssl (error, "Can't compute sha512 operation");
          return NULL;
        }
    }

  guint digest_len = EVP_MD_CTX_size (ctx);
  g_autofree char *digest = g_malloc (digest_len);
  if (EVP_DigestFinal_ex (ctx, (guchar *)digest, &digest_len) == 0)
    {
      fail_ssl (error, "Can't compute sha512 operation");
      return NULL;
    }

  if (fd_out)
    {
      lseek (fd, 0, SEEK_SET);
      *fd_out = steal_fd (&fd);
    }
  *digest_len_out = digest_len;
  return g_steal_pointer (&digest);
}

gboolean
load_file_data_for_sign (const char *path, struct stat *st, int *type_out, guchar **content_out,
                         gsize *content_len_out, int *fd_out, GError **error)
{

  struct stat st_buf;
  if (st == NULL)
    {
      int res = lstat (path, &st_buf);
      if (res < 0)
        {
          g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Can't stat %s: %s",
                       path, strerror (errno));
          return FALSE;
        }
      st = &st_buf;
    }

  int type = st->st_mode & S_IFMT;
  if (type != S_IFREG && type != S_IFLNK)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno), "Unsupported file tye %s",
                   path);
      return FALSE;
    }

  g_autofree char *content = NULL;
  gsize content_len = 0;
  autofd int fd = -1;

  if (type == S_IFREG)
    {
      content = sha512_file (path, &content_len, fd_out ? &fd : NULL, error);
      if (content == NULL)
        return FALSE;
    }
  else
    {
      content = g_file_read_link (path, error);
      if (content == NULL)
        return FALSE;
      content_len = strlen (content);
    }

  if (fd_out)
    *fd_out = steal_fd (&fd);
  if (type_out)
    *type_out = type;
  *content_out = (guchar *)g_steal_pointer (&content);
  *content_len_out = content_len;

  return TRUE;
}

gboolean
sign_data (int type, const char *rel_path, const guchar *content, gsize content_len, EVP_PKEY *pkey,
           guchar **signature_out, gsize *signature_len_out, GError **error)
{
  gsize to_sign_len;
  g_autofree guchar *to_sign
      = make_sign_blob (rel_path, type, content, content_len, &to_sign_len, error);
  if (to_sign == NULL)
    return FALSE;

  g_autoptr (EVP_MD_CTX) ctx = EVP_MD_CTX_new ();
  if (!ctx)
    return fail_ssl (error, "Can't init context");

  if (EVP_DigestSignInit (ctx, NULL, NULL, NULL, pkey) == 0)
    return fail_ssl (error, "Can't initialize signature operation");

  gsize signature_len = 0;
  if (EVP_DigestSign (ctx, NULL, &signature_len, to_sign, to_sign_len) == 0)
    return fail_ssl (error, "Error getting signature size");

  g_autofree guchar *signature = g_malloc (VALIDATOR_SIGNATURE_MAGIC_LEN + signature_len);
  memcpy (signature, VALIDATOR_SIGNATURE_MAGIC, VALIDATOR_SIGNATURE_MAGIC_LEN);
  if (EVP_DigestSign (ctx, signature + VALIDATOR_SIGNATURE_MAGIC_LEN, &signature_len, to_sign,
                      to_sign_len)
      == 0)
    return fail_ssl (error, "Error signing data");

  *signature_out = g_steal_pointer (&signature);
  *signature_len_out = VALIDATOR_SIGNATURE_MAGIC_LEN + signature_len;

  return TRUE;
}

gboolean
has_path_prefix (const char *str, const char *prefix)
{
  while (TRUE)
    {
      /* Skip consecutive slashes to reach next path
         element */
      while (*str == '/')
        str++;
      while (*prefix == '/')
        prefix++;

      /* No more prefix path elements? Done! */
      if (*prefix == 0)
        return TRUE;

      /* Compare path element */
      while (*prefix != 0 && *prefix != '/')
        {
          if (*str != *prefix)
            return FALSE;
          str++;
          prefix++;
        }

      /* Matched prefix path element,
         must be entire str path element */
      if (*str != '/' && *str != 0)
        return FALSE;
    }
}

int
write_to_fd (int fd, const guchar *content, gsize len)
{
  gssize res;

  while (len > 0)
    {
      res = TEMP_FAILURE_RETRY (write (fd, content, len));
      if (res <= 0)
        {
          if (res == 0) /* Unexpected short write, should not happen when writing to a file */
            errno = ENOSPC;
          return -1;
        }
      len -= res;
      content += res;
    }

  return 0;
}

int
copy_fd (int from_fd, int to_fd)
{
  while (TRUE)
    {
      guchar buf[16 * 1024];
      gssize n = TEMP_FAILURE_RETRY (read (from_fd, buf, sizeof (buf)));
      if (n < 0)
        return -1;

      if (n == 0) /* EOF */
        break;

      if (write_to_fd (to_fd, buf, (size_t)n) < 0)
        return -1;
    }

  return 0;
}

static gboolean
is_notfound (GError *error)
{
  return g_error_matches (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND)
         || g_error_matches (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND);
}

gboolean
keyfile_get_boolean_with_default (GKeyFile *keyfile, const char *section, const char *value,
                                  gboolean default_value, gboolean *out_bool, GError **error)
{
  g_return_val_if_fail (keyfile != NULL, FALSE);
  g_return_val_if_fail (section != NULL, FALSE);
  g_return_val_if_fail (value != NULL, FALSE);

  GError *temp_error = NULL;
  gboolean ret_bool = g_key_file_get_boolean (keyfile, section, value, &temp_error);
  if (temp_error)
    {
      if (is_notfound (temp_error))
        {
          g_clear_error (&temp_error);
          ret_bool = default_value;
        }
      else
        {
          g_propagate_error (error, temp_error);
          return FALSE;
        }
    }

  *out_bool = ret_bool;
  return TRUE;
}

gboolean
keyfile_get_value_with_default (GKeyFile *keyfile, const char *section, const char *value,
                                const char *default_value, char **out_value, GError **error)
{
  g_return_val_if_fail (keyfile != NULL, FALSE);
  g_return_val_if_fail (section != NULL, FALSE);
  g_return_val_if_fail (value != NULL, FALSE);

  GError *temp_error = NULL;
  g_autofree char *ret_value = g_key_file_get_value (keyfile, section, value, &temp_error);
  if (temp_error)
    {
      if (is_notfound (temp_error))
        {
          g_clear_error (&temp_error);
          g_assert (ret_value == NULL);
          ret_value = g_strdup (default_value);
        }
      else
        {
          g_propagate_error (error, temp_error);
          return FALSE;
        }
    }

  *out_value = g_steal_pointer (&ret_value);
  return TRUE;
}

gboolean
keyfile_get_string_list_with_default (GKeyFile *keyfile, const char *section, const char *key,
                                      char separator, char **default_value, char ***out_value,
                                      GError **error)
{
  g_autoptr (GError) temp_error = NULL;

  g_return_val_if_fail (keyfile != NULL, FALSE);
  g_return_val_if_fail (section != NULL, FALSE);
  g_return_val_if_fail (key != NULL, FALSE);

  g_key_file_set_list_separator (keyfile, separator);

  g_auto (GStrv) ret_value = g_key_file_get_string_list (keyfile, section, key, NULL, &temp_error);

  if (temp_error)
    {
      if (is_notfound (temp_error))
        {
          g_clear_error (&temp_error);
          ret_value = g_strdupv (default_value);
        }
      else
        {
          g_propagate_error (error, g_steal_pointer (&temp_error));
          return FALSE;
        }
    }

  *out_value = g_steal_pointer (&ret_value);
  return TRUE;
}
