"""Safe sample: parameterised queries only."""


def get_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
