CLASS ltc_service DEFINITION FINAL FOR TESTING RISK LEVEL HARMLESS DURATION SHORT.
  PRIVATE SECTION.
    METHODS places FOR TESTING.
ENDCLASS.

CLASS ltc_service IMPLEMENTATION.
  METHOD places.
    DATA(lo_service) = NEW zcl_order_service( ).
    cl_abap_unit_assert=>assert_equals( act = lo_service->place( 'book' ) exp = 'book' ).
  ENDMETHOD.
ENDCLASS.
