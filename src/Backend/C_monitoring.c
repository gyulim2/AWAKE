#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16)) // 버퍼 크기

int main() {
    int length, i = 0;
    int fd;                // inotify 파일 디스크립터
    int wd;                // 감시할 디렉토리의 워치 디스크립터
    char buffer[BUF_LEN];  // 이벤트 버퍼

    const char *watch_dir = "/home/fol/A_Awake/monitor_test";  // 감시할 디렉토리
    const char *script_path = "../Python/python_script.py";       // 실행할 Python 스크립트 경로

    // inotify 인스턴스 생성
    fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }

    // 디렉토리에 대한 감시 추가 (생성 이벤트)
    wd = inotify_add_watch(fd, watch_dir, IN_CREATE);
    if (wd == -1) {
        fprintf(stderr, "Could not watch : %s\n", watch_dir);
        exit(EXIT_FAILURE);
    } else {
        printf("Watching: %s\n", watch_dir);
    }

    // 이벤트 수신 대기
    while (1) {
        length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            perror("read");
        }

        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];

            if (event->len) {
                if (event->mask & IN_CREATE) {  // 파일 생성 이벤트 감지
                    printf("New file detected: %s\n", event->name);

                    // Python 스크립트 실행
                    char command[512];
                    snprintf(command, sizeof(command), "python3 %s %s/%s", script_path, watch_dir, event->name);
                    int ret = system(command);
                }
            }
            i += EVENT_SIZE + event->len;
        }
        i = 0;
    }

    // inotify 감시 해제 및 종료
    inotify_rm_watch(fd, wd);
    close(fd);

    return 0;
}

