from app.utils.strings import slug
from app.utils.money import cents


def monthly(rows):
    return [slug(r) + str(cents(1)) for r in rows]
