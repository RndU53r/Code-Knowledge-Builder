CLASS zcl_handler DEFINITION PUBLIC CREATE PUBLIC.
  PUBLIC SECTION.
    INTERFACES if_http_extension.
ENDCLASS.

CLASS zcl_handler IMPLEMENTATION.
  METHOD if_http_extension~handle_request.
    DATA(lv_id) = server->request->get_form_field( 'id' ).
    SELECT * FROM zorders INTO TABLE @DATA(lt_orders) WHERE (lv_id).
  ENDMETHOD.
ENDCLASS.
