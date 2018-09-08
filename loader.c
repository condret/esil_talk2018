#include <r_core.h>
#include <r_anal.h>

void entry (void *user) {
	RCore *core = (RCore *)user;

	if (!core || !core->anal || !core->anal->esil) {
		return;
	}
	r_anal_esil_load_interrupts_from_lib(core->anal->esil, "./my_interrupts.so");
}
