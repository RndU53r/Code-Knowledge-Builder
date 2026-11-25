import argparse
from celery import shared_task


@shared_task
def send_receipt(order_id, email):
    return f"sent {order_id} to {email}"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run")
    return p.parse_args()
