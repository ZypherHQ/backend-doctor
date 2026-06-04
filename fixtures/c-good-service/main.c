#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

size_t read_name(FILE *input, char **line) {
    size_t capacity = 0;
    ssize_t read = getline(line, &capacity, input);
    if (read < 0) {
        return 0;
    }

    (*line)[strcspn(*line, "\n")] = '\0';
    return (size_t)read;
}

int main(void) {
    char *line = NULL;
    size_t length = read_name(stdin, &line);
    if (length > 0) {
        printf("hello %s\n", line);
    }
    free(line);
    return 0;
}
