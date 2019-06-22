#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void test_dummy(void ** state) {
    (void) state;

    assert_false(0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dummy)
    };

    return cmocka_run_group_tests_name("lurch_api", tests, NULL, NULL);
}