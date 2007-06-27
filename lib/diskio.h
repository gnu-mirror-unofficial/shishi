/* diskio.h --- Read and write data structures from disk.
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

extern int _shishi_print_armored_data (Shishi * handle, FILE * fh,
				       Shishi_asn1 asn1,
				       const char *asn1type, char *headers);
extern int _shishi_save_data (Shishi * handle, FILE * fh, Shishi_asn1 asn1,
			      const char *asn1type);
extern int _shishi_authenticator_input (Shishi * handle,
					FILE * fh,
					Shishi_asn1 * authenticator,
					int type);
extern int _shishi_apreq_input (Shishi * handle, FILE * fh,
				Shishi_asn1 * apreq, int type);
extern int _shishi_aprep_input (Shishi * handle, FILE * fh,
				Shishi_asn1 * aprep, int type);
extern int _shishi_kdcreq_input (Shishi * handle, FILE * fh,
				 Shishi_asn1 * asreq, int type);
extern int _shishi_kdcrep_input (Shishi * handle, FILE * fh,
				 Shishi_asn1 * asrep, int type);
extern int _shishi_krberror_input (Shishi * handle, FILE * fh,
				   Shishi_asn1 * krberror, int type);
extern int _shishi_encapreppart_input (Shishi * handle, FILE * fh,
				       Shishi_asn1 * encapreppart, int type);
extern int _shishi_safe_input (Shishi * handle, FILE * fh, Shishi_asn1 * safe,
			       int type);
extern int _shishi_priv_input (Shishi * handle, FILE * fh, Shishi_asn1 * priv,
			       int type);
