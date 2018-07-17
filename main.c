#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    printf("h3c v0.1.0 build 001 - A command line tool for H3C 802.1X authentication\n");
    printf("Copyright (c) 2018 Tommy Lau <tommy@gen-new.com>\n\n");

    static struct option options[] = {
            {"help",      no_argument,       NULL, 'h'},
            {"user",      required_argument, NULL, 'u'},
            {"password",  required_argument, NULL, 'p'},
            {"interface", optional_argument, NULL, 'i'},
            {"method",    optional_argument, NULL, 'd'},
            {NULL, 0,                        NULL, 0}
    };

    int c;
    char *interface = NULL;
    char *username = NULL;
    char *password = NULL;
    bool md5 = true;

    while ((c = getopt_long(argc, argv, "hu:p:i:m:", options, NULL)) != -1) {
        switch (c) {
            case 'h':
                printf(
                        "Usage: h3c [options]\n"
                        "-h, --help          This help text\n"
                        "-i, --interface     Network interface (Default: en0)\n"
                        "-m, --method        EAP-MD5 CHAP Method [md5 / xor] (Default: md5)\n"
                        "-p, --password      Password\n"
                        "-u, --username      Username\n"
                );
                return EXIT_SUCCESS;

            case 'i':
                interface = optarg;
                break;

            case 'm':
                if (strcmp(optarg, "md5") == 0)
                    md5 = true;
                else if (strcmp(optarg, "xor") == 0)
                    md5 = false;
                else {
                    fprintf(stderr, "Method can only be either \"md5\" or \"xor\"\n");
                    return EXIT_FAILURE;
                }
                break;

            case 'p':
                password = optarg;
                break;

            case 'u':
                username = optarg;
                break;

            default:
                fprintf(stderr, "Invalid arguments.\n");
                return EXIT_FAILURE;
        }
    }

#if NDEBUG
    if (geteuid() != 0) {
        printf("You have to run this program as root.\n");
        exit(EXIT_FAILURE);
    }
#endif

    if (interface == NULL)
        interface = "en0";

    if (username == NULL) {
        fprintf(stderr, "Please input username.\n");
        return EXIT_FAILURE;
    }

    if (password == NULL) {
        password = getpass("Password: ");
    }

    if (strlen(password) == 0) {
        fprintf(stderr, "Incorrect password.");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Username '%s' with password '%s', interface: %s, md5: %d\n",
            username, password, interface, md5);

    return EXIT_SUCCESS;
}
