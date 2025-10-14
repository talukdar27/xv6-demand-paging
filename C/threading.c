#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#define MAX_CAPACITY 25
#define SOFA_SEATS 4
#define NUM_CHEFS 4

#define CUSTOMER_ACTION_SEC 1
#define CHEF_ACTION_SEC 2

sem_t capacity_sem;
sem_t sofa_sem;
sem_t cash_register;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t work_available = PTHREAD_COND_INITIALIZER;

typedef struct customer customer_t;

typedef struct node {
    customer_t *cust;
    struct node *next;
} node_t;

typedef struct queue {
    node_t *head;
    node_t *tail;
    int size;
} queue_t;

static void queue_init(queue_t *q) { q->head = q->tail = NULL; q->size = 0; }
static void queue_push(queue_t *q, customer_t *c) {
    node_t *n = malloc(sizeof(node_t));
    n->cust = c;
    n->next = NULL;
    if (q->tail){
        q->tail->next = n;
    } else {
        q->head = n;
    }
    q->tail = n;
    q->size++;
}
static customer_t *queue_pop(queue_t *q) {
    if (!q->head) return NULL;
    node_t *n = q->head;
    customer_t *c = n->cust;
    q->head = n->next;
    if (!q->head){
        q->tail = NULL;
    }
    free(n);
    q->size--;
    return c;
}
static int queue_size(queue_t *q) { return q->size; }

queue_t sofa_queue;
queue_t standing_queue;
queue_t payment_queue;

struct customer {
    int id;
    int arrival_time;
    sem_t served_sem;
    sem_t cake_done_sem;
    sem_t payment_done_sem;
    sem_t sit_sem;
    sem_t request_sem;
};

time_t sim_start;

static void log_msg(const char *fmt, ...) {
    time_t now;
    time(&now);
    int rel_time = (int)(now - sim_start);

    printf("%d ", rel_time);

    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    printf("\n");
    fflush(stdout);
}

void *customer_thread(void *arg) {
    customer_t *c = (customer_t *)arg;

    time_t now;
    while (1) {
        time(&now);
        int elapsed = (int)(now - sim_start);
        if (elapsed >= c->arrival_time) break;
        usleep(100000);
    }

    if (sem_trywait(&capacity_sem) != 0) {
        log_msg("Customer %d could not enter (bakery full)", c->id);
        goto cleanup_no_enter;
    }

    log_msg("Customer %d enters", c->id);
    sleep(CUSTOMER_ACTION_SEC);

    if (sem_trywait(&sofa_sem) == 0) {
        log_msg("Customer %d sits", c->id);
        pthread_mutex_lock(&queue_mutex);
        queue_push(&sofa_queue, c);
        pthread_cond_broadcast(&work_available);
        pthread_mutex_unlock(&queue_mutex);
        sleep(CUSTOMER_ACTION_SEC);
    } else {
        pthread_mutex_lock(&queue_mutex);
        queue_push(&standing_queue, c);
        pthread_mutex_unlock(&queue_mutex);

        sem_wait(&c->sit_sem);
        sem_wait(&sofa_sem);
        log_msg("Customer %d sits", c->id);
        pthread_mutex_lock(&queue_mutex);
        queue_push(&sofa_queue, c);
        pthread_cond_broadcast(&work_available);
        pthread_mutex_unlock(&queue_mutex);
        sleep(CUSTOMER_ACTION_SEC);
    }

    log_msg("Customer %d requests cake", c->id);
    sem_post(&c->request_sem);
    sleep(CUSTOMER_ACTION_SEC);

    sem_wait(&c->cake_done_sem);
    log_msg("Customer %d pays", c->id);
    sleep(CUSTOMER_ACTION_SEC);

    pthread_mutex_lock(&queue_mutex);
    queue_push(&payment_queue, c);
    pthread_cond_broadcast(&work_available);
    pthread_mutex_unlock(&queue_mutex);

    sem_wait(&c->payment_done_sem);
    log_msg("Customer %d leaves", c->id);

    sem_post(&sofa_sem);

    pthread_mutex_lock(&queue_mutex);
    if (queue_size(&standing_queue) > 0) {
        customer_t *promoted = queue_pop(&standing_queue);
        sem_post(&promoted->sit_sem);
    }
    pthread_mutex_unlock(&queue_mutex);

    sem_post(&capacity_sem);

cleanup_no_enter:
    free(c);
    return NULL;
}

void *chef_thread(void *arg) {
    int chef_id = *(int *)arg;
    free(arg);

    while (1) {
        pthread_mutex_lock(&queue_mutex);

        while (queue_size(&payment_queue) == 0 && queue_size(&sofa_queue) == 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&work_available, &queue_mutex, &ts);
        }

        if (queue_size(&payment_queue) > 0) {
            if (sem_trywait(&cash_register) == 0) {
                customer_t *pay_c = queue_pop(&payment_queue);
                pthread_mutex_unlock(&queue_mutex);

                if (pay_c) {
                    log_msg("Chef %d accepts payment from Customer %d", chef_id, pay_c->id);
                    sleep(CHEF_ACTION_SEC);
                    sem_post(&pay_c->payment_done_sem);
                }

                sem_post(&cash_register);
                continue;
            }
        }

        customer_t *svc = queue_pop(&sofa_queue);
        pthread_mutex_unlock(&queue_mutex);

        if (svc) {
            sem_wait(&svc->request_sem);
            sleep(CUSTOMER_ACTION_SEC);
            log_msg("Chef %d starts baking for Customer %d", chef_id, svc->id);

            sleep(CHEF_ACTION_SEC);

            sem_post(&svc->cake_done_sem);
        }
    }

    return NULL;
}


void spawn_customer(int cid, int arrival_sec) {
    customer_t *c = calloc(1, sizeof(customer_t));
    c->id = cid;
    c->arrival_time = arrival_sec;
    sem_init(&c->served_sem, 0, 0);
    sem_init(&c->cake_done_sem, 0, 0);
    sem_init(&c->payment_done_sem, 0, 0);
    sem_init(&c->sit_sem, 0, 0);
    sem_init(&c->request_sem, 0, 0);

    pthread_t tid;
    if (pthread_create(&tid, NULL, customer_thread, c) != 0) {
        log_msg("Failed to create customer thread %d: %s", cid, strerror(errno));
        free(c);
        return;
    }
    pthread_detach(tid);
}

int main() {
    time(&sim_start);
    log_msg("Simulation starting.");

    sem_init(&capacity_sem, 0, MAX_CAPACITY);
    sem_init(&sofa_sem, 0, SOFA_SEATS);
    sem_init(&cash_register, 0, 1);

    queue_init(&sofa_queue);
    queue_init(&standing_queue);
    queue_init(&payment_queue);

    for (int i = 1; i <= NUM_CHEFS; ++i) {
        pthread_t tid;
        int *arg = malloc(sizeof(int));
        *arg = i;
        if (pthread_create(&tid, NULL, chef_thread, arg) != 0) {
            log_msg("Failed to spawn chef %d", i);
            free(arg);
            exit(1);
        }
        pthread_detach(tid);
    }

    FILE *fp = fopen("/home/user/Desktop/SEMESTER5/mini-project-2-talukdar27/C/input.txt", "r");
    if (!fp) {
        perror("Error opening input file");
        exit(1);
    }

    char line[128];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '\n' || line[0] == '#') continue;

        int timestamp, cust_id;
        if (sscanf(line, "%d Customer %d", &timestamp, &cust_id) == 2) {
            spawn_customer(cust_id, timestamp);
        } else {
            log_msg("Invalid input line: %s", line);
        }
    }

    fclose(fp);

    sleep(60);
    log_msg("Simulation ending.");
    return 0;
}