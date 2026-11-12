"""Vulnerable sample: SQL injection via string-built queries."""


def get_user(cursor, user_id, username, order_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)
    query = "SELECT * FROM orders WHERE id = " + order_id
    cursor.execute(query)
