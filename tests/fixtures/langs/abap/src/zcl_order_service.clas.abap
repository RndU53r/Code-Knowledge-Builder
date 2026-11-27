CLASS zcl_order_service DEFINITION PUBLIC FINAL CREATE PUBLIC.
  PUBLIC SECTION.
    METHODS place IMPORTING iv_item TYPE string RETURNING VALUE(rv_id) TYPE string.
  PRIVATE SECTION.
    DATA mo_repo TYPE REF TO zcl_order_repo.
ENDCLASS.

CLASS zcl_order_service IMPLEMENTATION.
  METHOD place.
    DATA lv_url TYPE string.
    DATA lo_client TYPE REF TO if_http_client.
    lv_url = |http://billing/charge/{ iv_item }|.
    cl_http_client=>create_by_url( EXPORTING url = lv_url IMPORTING client = lo_client ).
    CALL FUNCTION 'Z_BILLING_CHARGE' DESTINATION 'BILLING' EXPORTING iv_item = iv_item.
    rv_id = mo_repo->save( iv_item ).
  ENDMETHOD.
ENDCLASS.
