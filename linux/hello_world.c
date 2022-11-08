#include <unistd.h>
int main(){
const char msg[] = "Hello World!";
write(STDOUT_FILENO, msg, sizeof(msg)-1);
}
