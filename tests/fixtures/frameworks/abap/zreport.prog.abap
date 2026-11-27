REPORT zreport.
PARAMETERS p_file TYPE string.

START-OF-SELECTION.
  PERFORM run USING p_file.

FORM run USING iv_file TYPE string.
  CALL FUNCTION 'SXPG_COMMAND_EXECUTE' EXPORTING commandname = iv_file.
ENDFORM.
