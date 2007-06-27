/* starttls.h --- Network I/O functions for Shishi over TLS.
 * Copyright (C) 2002, 2003, 2004, 2007  Simon Josefsson
 *
 * This file is part of Shishi.
 *
 * Shishi is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Shishi is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Shishi; if not, see http://www.gnu.org/licenses or write
 * to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA
 *
 */

extern int _shishi_tls_init (Shishi * handle);
extern int _shishi_tls_done (Shishi * handle);
extern int _shishi_sendrecv_tls (Shishi * handle,
				 struct sockaddr *addr,
				 const char *indata, size_t inlen,
				 char **outdata, size_t *outlen,
				 size_t timeout, Shishi_tkts_hint * hint);
