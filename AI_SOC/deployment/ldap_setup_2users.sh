#!/bin/bash
# ldap_setup_2users.sh - Two user setup for Windows VM simulation

LDAP_CONTAINER="casb-ldap"
DOMAIN="dc=casb,dc=local"
ADMIN_PASS="${LDAP_ADMIN_PASSWORD:-CHANGE_ME}"

echo "[+] Removing old test users..."
docker exec -i $LDAP_CONTAINER ldapdelete -x -D "cn=admin,$DOMAIN" -w $ADMIN_PASS \
  "cn=marcus_redteam,ou=People,$DOMAIN" 2>/dev/null || true
docker exec -i $LDAP_CONTAINER ldapdelete -x -D "cn=admin,$DOMAIN" -w $ADMIN_PASS \
  "cn=kevin_contractor,ou=People,$DOMAIN" 2>/dev/null || true
docker exec -i $LDAP_CONTAINER ldapdelete -x -D "cn=admin,$DOMAIN" -w $ADMIN_PASS \
  "cn=admin_test,ou=People,$DOMAIN" 2>/dev/null || true

echo "[+] Creating 2 production users..."

# User 1: standard_user (Standard/limited Windows user)
docker exec -i $LDAP_CONTAINER ldapadd -x -D "cn=admin,$DOMAIN" -w $ADMIN_PASS <<EOF
dn: cn=standard_user,ou=People,$DOMAIN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: standard_user
sn: Standard
uid: standard_user
uidNumber: 10001
gidNumber: 5000
homeDirectory: /home/standard_user
loginShell: /bin/bash
mail: standard@casb.local
description: Standard endpoint user - Windows10 VM .60
EOF

# User 2: dev_user (Elevated developer - higher AI quota + model access)
docker exec -i $LDAP_CONTAINER ldapadd -x -D "cn=admin,$DOMAIN" -w $ADMIN_PASS <<EOF
dn: cn=dev_user,ou=People,$DOMAIN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: dev_user
sn: Developer
uid: dev_user
uidNumber: 10002
gidNumber: 5001
homeDirectory: /home/dev_user
loginShell: /bin/bash
mail: dev@casb.local
description: Elevated dev user - Windows10 VM .60 - Higher CASB trust tier
EOF

echo ""
echo "[+] Verifying users..."
docker exec $LDAP_CONTAINER ldapsearch -x -D "cn=admin,$DOMAIN" -w $ADMIN_PASS \
  -b "ou=People,$DOMAIN" "(objectClass=inetOrgPerson)" uid mail description | grep -E "^(uid|mail|description):"

echo ""
echo "[✔] LDAP setup complete: standard_user + dev_user"
