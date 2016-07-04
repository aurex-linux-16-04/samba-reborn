##!/usr/bin/env python
import base64
import binascii
import sys
import ldap

def nt2unicode_pwd(ldap_samba_nt_password):
	b64_hash = base64.b64encode(binascii.a2b_hex(ldap_samba_nt_password))
	return b64_hash

def ldap_bind(ldapserver, binddn, bindpass):
	ld = ldap.initialize(ldapserver)
	ld.protocol_version = ldap.VERSION3
	ld.simple_bind_s(binddn, bindpass)
	return ld

def ldap_listgroups(ld, groupdn):
	searchScope = ldap.SCOPE_SUBTREE
	retrieveAttributes = [ 'cn', 'memberuid' ] 
	searchFilter = "objectclass=posixGroup"
	ldap_result_id = ld.search(groupdn, searchScope, searchFilter, retrieveAttributes)
	glist =[]
	while 1:
		result_type, result_data = ld.result(ldap_result_id, 0)i
		if (result_data == []):
			break
		else:
			if result_type == ldap.RES_SEARCH_ENTRY:
				glist.append([ result_data[0][1]['cn'][0], result_data[0][1]['memberuid'])


