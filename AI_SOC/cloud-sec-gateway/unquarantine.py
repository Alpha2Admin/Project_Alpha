from risk_scoring import db_connect

def unquarantine(user):
    conn = db_connect()
    c = conn.cursor()
    c.execute("DELETE FROM user_risk WHERE user = ?", (user,))
    c.execute("DELETE FROM risk_events WHERE user = ?", (user,))
    conn.commit()
    conn.close()
    print(f"User {user} risk reset.")

unquarantine("dev_user")
unquarantine("standard_user")
