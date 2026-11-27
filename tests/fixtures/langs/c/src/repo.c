#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include "repo.h"

static sqlite3 *db;

int save_order(const char *item)
{
    char sql[256];
    char note[32];
    strcpy(note, item);
    snprintf(sql, sizeof(sql), "INSERT INTO orders(item) VALUES ('%s')", item);
    return sqlite3_exec(db, sql, NULL, NULL, NULL);
}
