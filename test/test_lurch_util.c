#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/lurch_util.h"

void __wrap_purple_debug_error(const char * category, const char * format, ...) {
    function_called();
}

const char * __wrap_purple_user_dir(void) {
    char * user_dir;
    user_dir = mock_ptr_type(char *);
    return user_dir;
}

/**
 * Log only errors when log level is set to AXC_LOG_ERROR, using purple_debug_error().
 */
/*
static void test_lurch_util_axc_log_func_error(void ** state) {
    (void) state;

    axc_context * axc_ctx_p = (void *) 0;

    (void) axc_context_create(&axc_ctx_p);
    axc_context_set_log_level(axc_ctx_p, AXC_LOG_ERROR);
    expect_function_call(_-__wrap_purple_debug_error);

    lurch_util_axc_log_func

    assert_false(1);


    axc_context_destroy_all(axc_ctx_p);
}
*/

static void test_lurch_util_uname_get_db_fn(void ** state) {
    (void) state;

    will_return(__wrap_purple_user_dir, "/home/testuser/.purple");

    assert_string_equal(lurch_util_uname_get_db_fn("test-uname@example.com", "TESTTYPE"),
    "/home/testuser/.purple/test-uname@example.com_TESTTYPE_db.sqlite");
}

static void test_lurch_util_fp_get_printable(void ** state) {
    (void) state;

    const char * fp_as_returned_by_pidgin =
        "12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:ab:cd:ef";

    char * printable_fp = lurch_util_fp_get_printable(fp_as_returned_by_pidgin);
    assert_non_null(printable_fp);
    assert_string_equal(printable_fp, "34567812 34567812 34567812 34567812 34567812 34567812 34567812 abcdef");

}

static void test_lurch_util_fp_get_printable_invalid(void ** state) {
    (void) state;

    assert_null(lurch_util_fp_get_printable(NULL));

    const char * too_short =
        "12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:ab:cdef";
    const char * too_long =
        "12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:34:56:78:12:ab:cd:ef:";

    assert_null(lurch_util_fp_get_printable(too_short));
    assert_null(lurch_util_fp_get_printable(too_long));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_lurch_util_uname_get_db_fn),
        cmocka_unit_test(test_lurch_util_fp_get_printable),
        cmocka_unit_test(test_lurch_util_fp_get_printable_invalid)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}