#!/bin/bash
# ldap_setup.sh - Populate OpenLDAP with AI-CASB identities

LDAP_CONTAINER="casb-ldap"
DOMAIN="dc=casb,dc=local"
ADMIN_PASS="${LDAP_ADMIN_PASSWORD:-CHANGE_ME}"

echo "[+] Creating Organizational Units..."
docker exec -i $LDAP_CONTAINER ldapadd -x -D "cn=admin,$DOMAIN" -w $ADMIN_PASS <<EOF
dn: ou=People,$DOMAIN
objectClass: organizationalUnit
ou: People

dn: ou=Groups,$DOMAIN
objectClass: organizationalUnit
ou: Groups
EOF

echo "[+] Creating Test Users..."

# User 1: marcus_redteam (The Attacker)
docker exec -i $LDAP_CONTAINER ldapadd -x -D "cn=admin,$DOMAIN" -w $ADMIN_PASS <<EOF
dn: cn=marcus_redteam,ou=People,$DOMAIN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: marcus_redteam
sn: RedTeam
uid: marcus_redteam
uidNumber: 10001
gidNumber: 5000
homeDirectory: /home/marcus_redteam
loginShell: /bin/bash
userPassword: REDACTED_LDAP_HASH
EOF

# User 2: kevin_contractor (The Insider Threat)
docker exec -i $LDAP_CONTAINER ldapadd -x -D "cn=admin,$DOMAIN" -w $ADMIN_PASS <<EOF
dn: cn=kevin_contractor,ou=People,$DOMAIN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: kevin_contractor
sn: Contractor
uid: kevin_contractor
uidNumber: 10002
gidNumber: 5000
homeDirectory: /home/kevin_contractor
loginShell: /bin/bash
userPassword: REDACTED_LDAP_HASH
EOF

# User 3: admin_test (The Authorized User)
docker exec -i $LDAP_CONTAINER ldapadd -x -D "cn=admin,$DOMAIN" -w $ADMIN_PASS <<EOF
dn: cn=admin_test,ou=People,$DOMAIN
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
cn: admin_test
sn: Admin
uid: admin_test
uidNumber: 10003
gidNumber: 5000
homeDirectory: /home/admin_test
loginShell: /bin/bash
userPassword: REDACTED_LDAP_HASH
EOF

echo "[✔] LDAP Population Complete!"
