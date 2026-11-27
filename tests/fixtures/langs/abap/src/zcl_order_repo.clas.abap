CLASS zcl_order_repo DEFINITION PUBLIC
  INHERITING FROM zcl_base_repo
  CREATE PUBLIC.
  PUBLIC SECTION.
    INTERFACES zif_repo.
    METHODS save REDEFINITION.
ENDCLASS.

CLASS zcl_order_repo IMPLEMENTATION.
  METHOD save.
    DATA lv_sql TYPE string.
    DATA lo_stmt TYPE REF TO cl_sql_statement.
    lv_sql = |INSERT INTO zorders ( item ) VALUES ( '{ iv_item }' )|.
    lo_stmt->execute_update( lv_sql ).
    rv_id = iv_item.
  ENDMETHOD.
ENDCLASS.
