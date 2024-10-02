#include <string.h>
#include <unistd.h>

void __attribute__((noinline)) change_buf(char param[12]) {
	memcpy(param, "alter, world", 12);
}

int main(void) {
	char buf[12];

	while (1) {
		memcpy(buf, "hello, world", 12);;
		//write(1, buf, 12);
		//write(1, "\n", 1);
		change_buf(buf);
		//write(1, buf, 12);
		//write(1, "\n", 1);
		sleep(1);
	}
	return 0;
}

