#!/bin/bash
# LDAP User Setup Script - PROVISIONING SCRIPT

# ==============================================================================
# WARNING: This script was previously hardcoded. Passwords must now be passed
# via environment variables. DO NOT hardcode passwords here.
# ==============================================================================

# Wait for LDAP to be ready
echo "Waiting for OpenLDAP to start..."
sleep 10

# Bind as LDAP admin
ADMIN_PASS="${LDAP_ADMIN_PASSWORD:-REPLACE_ME_LDAP_ADMIN_PASSWORD}"

# Load the base LDIF
cat <<EOF | ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=casb,dc=local" -w "$ADMIN_PASS"
dn: ou=users,dc=casb,dc=local
objectClass: organizationalUnit
ou: users

# User 1: john_doe (A standard user)
dn: uid=john_doe,ou=users,dc=casb,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: john_doe
sn: Doe
givenName: John
cn: John Doe
displayName: John Doe
uidNumber: 10001
gidNumber: 10000
userPassword: {SSHA}REPLACE_ME_LDAP_HASH
homeDirectory: /home/john_doe
loginShell: /bin/bash

# User 2: jane_smith (Another standard user)
dn: uid=jane_smith,ou=users,dc=casb,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: jane_smith
sn: Smith
givenName: Jane
cn: Jane Smith
displayName: Jane Smith
uidNumber: 10002
gidNumber: 10000
userPassword: {SSHA}REPLACE_ME_LDAP_HASH
homeDirectory: /home/jane_smith
loginShell: /bin/bash

# User 3: admin_test (The Authorized User)
dn: uid=admin_test,ou=users,dc=casb,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: admin_test
sn: Test
givenName: Admin
cn: Admin Test
displayName: Admin Test
uidNumber: 10003
gidNumber: 10000
userPassword: {SSHA}REPLACE_ME_LDAP_HASH
homeDirectory: /home/admin_test
loginShell: /bin/bash
EOF

echo "Users provisioned successfully."