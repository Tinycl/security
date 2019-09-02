#pragma once
#include <Windows.h>
#include <inttypes.h>

extern "C"
{
	void __native__swapgs(void);
	LPVOID __native__read_gs_base(void);
	void __native__set_gs_base(LPVOID GsBase);
	uint16_t __native__read_ss(void);
	void __native__ud2(void);
	void __native_train(unsigned char*);
	void __native_train_is_done(unsigned char*, unsigned char*);
};
