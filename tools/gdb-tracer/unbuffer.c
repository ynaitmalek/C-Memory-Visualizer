/* Linked into the traced binary only (never shown to students).
 * Makes stdout unbuffered so the tracer can read the output incrementally
 * from the redirected file after each step, without touching the user's code. */
#include <stdio.h>

__attribute__((constructor)) static void cviewer_unbuffer_stdout(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
}
