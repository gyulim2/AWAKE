/*
 * awake_monitor — 메일 수신 폴더를 inotify로 감시하다가 새 메일이 들어오면
 * 분석 파이프라인(python3 -m awake.pipeline --deliver <파일>)을 실행한다.
 *
 *   사용법: awake_monitor <감시할 폴더>
 *   환경변수: AWAKE_PYTHON  파이썬 실행 파일 (기본: python3)
 *             PYTHONPATH    awake 패키지가 있는 src/ 폴더 (scripts/run_monitor.sh가 설정)
 *
 * 예전 버전에서 고친 점
 *   - 감시 폴더·스크립트 경로 하드코딩 제거, 존재하지 않던 python_script.py 호출 수정
 *   - system()에 파일명을 이어 붙이던 방식(셸 명령 주입 가능) → fork/execvp로 인자를 그대로 전달
 *   - IN_CREATE(파일이 다 쓰이기 전에 발생) → IN_CLOSE_WRITE | IN_MOVED_TO (Maildir 배달은 rename)
 *   - 시작 시 이미 쌓여 있던 메일도 처리, SIGTERM/SIGINT로 정상 종료
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define BUF_LEN (64 * (sizeof(struct inotify_event) + NAME_MAX + 1))

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

/* 숨김 파일(Maildir 임시파일 등)과 경로 구분자가 든 이름은 처리하지 않는다 */
static int is_candidate(const char *name) {
    return name[0] != '\0' && name[0] != '.' && strchr(name, '/') == NULL;
}

static void analyze(const char *dir, const char *name) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path)) {
        fprintf(stderr, "[awake] 경로가 너무 김: %s\n", name);
        return;
    }

    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return; /* 이미 옮겨졌거나 일반 파일이 아님(심볼릭 링크 포함) */
    }

    const char *py = getenv("AWAKE_PYTHON");
    if (py == NULL || py[0] == '\0') py = "python3";

    printf("[awake] 새 메일: %s\n", name);
    fflush(stdout);

    pid_t pid = fork();
    if (pid < 0) {
        perror("[awake] fork");
        return;
    }
    if (pid == 0) {
        char *const argv[] = {(char *)py, "-m", "awake.pipeline", "--deliver", path, NULL};
        execvp(py, argv);
        perror("[awake] execvp");
        _exit(127);
    }

    /* 메일을 한 통씩 순서대로 처리한다 (그동안 들어온 이벤트는 inotify 큐에 쌓인다) */
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            perror("[awake] waitpid");
            return;
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "[awake] 분석 실패 (%s), 메일은 그대로 둡니다\n", name);
    }
}

static void process_existing(const char *dir) {
    DIR *d = opendir(dir);
    if (d == NULL) return;
    struct dirent *e;
    while (!g_stop && (e = readdir(d)) != NULL) {
        if (is_candidate(e->d_name)) analyze(dir, e->d_name);
    }
    closedir(d);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "사용법: %s <감시할 폴더>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *dir = argv[1];

    struct sigaction sa = {0};
    sa.sa_handler = on_signal; /* SA_RESTART 없이: read()가 EINTR로 깨어나 종료 확인 */
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    int fd = inotify_init1(IN_CLOEXEC);
    if (fd < 0) {
        perror("inotify_init1");
        return EXIT_FAILURE;
    }
    if (inotify_add_watch(fd, dir, IN_CLOSE_WRITE | IN_MOVED_TO) < 0) {
        fprintf(stderr, "감시할 수 없음: %s (%s)\n", dir, strerror(errno));
        return EXIT_FAILURE;
    }
    printf("[awake] 감시 시작: %s\n", dir);
    fflush(stdout);

    process_existing(dir);

    char buf[BUF_LEN] __attribute__((aligned(__alignof__(struct inotify_event))));
    while (!g_stop) {
        ssize_t len = read(fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR) continue;
            perror("read");
            break;
        }
        for (char *p = buf; p < buf + len && !g_stop;) {
            const struct inotify_event *ev = (const struct inotify_event *)p;
            if (ev->len > 0 && !(ev->mask & IN_ISDIR) && is_candidate(ev->name)) {
                analyze(dir, ev->name);
            }
            p += sizeof(struct inotify_event) + ev->len;
        }
    }

    printf("[awake] 감시 종료\n");
    close(fd);
    return EXIT_SUCCESS;
}
