CLASS zcl_order_router DEFINITION PUBLIC INHERITING FROM cl_rest_http_handler CREATE PUBLIC.
  PUBLIC SECTION.
    METHODS if_rest_application~get_root_handler REDEFINITION.
ENDCLASS.

CLASS zcl_order_router IMPLEMENTATION.
  METHOD if_rest_application~get_root_handler.
    DATA(lo_router) = NEW cl_rest_router( ).
    lo_router->attach( iv_template = '/orders' iv_handler_class = 'ZCL_ORDER_CONTROLLER' ).
    ro_root_handler = lo_router.
  ENDMETHOD.
ENDCLASS.
