CLASS zcl_order_controller DEFINITION PUBLIC FINAL CREATE PUBLIC.
  PUBLIC SECTION.
    INTERFACES if_rest_resource.
  PRIVATE SECTION.
    DATA mo_service TYPE REF TO zcl_order_service.
ENDCLASS.

CLASS zcl_order_controller IMPLEMENTATION.
  METHOD if_rest_resource~post.
    AUTHORITY-CHECK OBJECT 'Z_ORDER' ID 'ACTVT' FIELD '01'.
    IF sy-subrc <> 0.
      RETURN.
    ENDIF.
    DATA(lv_item) = mo_request->get_uri_query_parameter( iv_name = 'item' ).
    CREATE OBJECT mo_service.
    mo_service->place( lv_item ).
  ENDMETHOD.
ENDCLASS.
