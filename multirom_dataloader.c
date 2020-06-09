#include "multirom_dataloader.h"
#include <minivcs.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <exception.h>
#include <stdlib.h>
#include <zconf.h>
#include "dirent.h"

#define REALDATA_PATH "/realdata"
#define VCS_DIRECTORY_NAME "vcs"
#define VCS_PATH REALDATA_PATH "/" VCS_DIRECTORY_NAME
#define LOAD_PROJECT_PATH REALDATA_PATH "/" "load_project"
#define BRANCH_NAME_MAX LINE_MAX
#define DATA_DISK_LOCATION REALDATA_PATH "/userdata"
#define DATA_PATH "/data"

int generate_config()
{
    DIR* dir = opendir(VCS_PATH);
    if(dir)
    {
        closedir(dir);
    }
    else if (errno == ENOENT)
    {
        if(mkdir(VCS_PATH, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }
    minivcs_generate_config(VCS_PATH);
    if(EXCEPTION_IS_THROWN)
    {
        errno = EXCEPTION_ERROR;
        return -1;
    }
    return 0;
}

int init_project(const char* password)
{
    int ret = 0;
    struct minivcs_project proj;
    minivcs_read_config(VCS_PATH, &proj);
    if(EXCEPTION_IS_THROWN)
    {
        errno = EXCEPTION_ERROR;
        return -1;
    }

    if(minivcs_need_password(&proj))
    {
        minivcs_set_password(password, &proj);
        if(EXCEPTION_IS_THROWN)
        {
            errno = EXCEPTION_ERROR;
            ret = -1;
            goto cleanup;
        }
    }

    minivcs_init_from_config(&proj);
    if(EXCEPTION_IS_THROWN)
    {
        errno = EXCEPTION_ERROR;
        ret = -1;
        goto cleanup;
    }

    cleanup:
    minivcs_destroy(&proj);
    return ret;
}

int recursive_remove(char* path)
{
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;

    if (d) {
        struct dirent *p;

        r = 0;
        while (!r && (p=readdir(d))) {
            int r2 = -1;
            char *buf;
            size_t len;

            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
                continue;

            len = path_len + strlen(p->d_name) + 2;
            buf = malloc(len);

            if (buf) {
                struct stat statbuf;

                snprintf(buf, len, "%s/%s", path, p->d_name);
                if (!lstat(buf, &statbuf)) {
                    if (S_ISDIR(statbuf.st_mode))
                        r2 = recursive_remove(buf);
                    else
                        r2 = unlink(buf);
                }
                free(buf);
            }
            r = r2;
        }
        closedir(d);
    }

    if (!r)
        r = rmdir(path);

    return r;
}

int store_previous_project(const char* password)
{
    char branch_name[BRANCH_NAME_MAX];
    {
        FILE *load_project = fopen(LOAD_PROJECT_PATH, "r");
        if(!load_project)
        {
            if(errno == ENOENT)
            {
                errno = 0;
                recursive_remove(DATA_DISK_LOCATION);
                return 0;
            }
            else
            {
                return -1;
            }
        }

        if(fread(branch_name, 1, BRANCH_NAME_MAX, load_project) == 0)
        {
            fclose(load_project);
            return -1;
        }
        char *branch_name_end = strchr(branch_name, '\n');
        if(branch_name_end)
        {
            *branch_name_end = '\0';
        }
        fclose(load_project);
    }
    int ret = 0;
    {
        struct minivcs_project proj;
        minivcs_read_config(VCS_PATH, &proj);
        if(EXCEPTION_IS_THROWN)
        {
            errno = EXCEPTION_ERROR;
            return -1;
        }

        if(minivcs_need_password(&proj))
        {
            minivcs_set_password(password, &proj);
            if(EXCEPTION_IS_THROWN)
            {
                errno = EXCEPTION_ERROR;
                ret = -1;
                goto cleanup;
            }
        }

        minivcs_update(branch_name, DATA_DISK_LOCATION, &proj);
        if(EXCEPTION_IS_THROWN)
        {
            errno = EXCEPTION_ERROR;
            ret -1;
            goto cleanup;
        }

        unlink(LOAD_PROJECT_PATH);
        recursive_remove(DATA_DISK_LOCATION);

        cleanup:
        minivcs_destroy(&proj);
    }
    return ret;
}

int extract_project(const char* branch_name, int use_ram, const char* password)
{
    int ret = 0;
    struct minivcs_project proj;
    minivcs_read_config(VCS_PATH, &proj);
    if(EXCEPTION_IS_THROWN)
    {
        errno = EXCEPTION_ERROR;
        return -1;
    }

    if(minivcs_need_password(&proj))
    {
        minivcs_set_password(password, &proj);
        if(EXCEPTION_IS_THROWN)
        {
            errno = EXCEPTION_ERROR;
            ret = -1;
            goto cleanup;
        }
    }

    if(mkdir(DATA_PATH, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
    {
        ret = -1;
        goto cleanup;
    }
    if(use_ram)
    {
        if(mount("tmpfs", DATA_PATH, "tmpfs", 0, "") < 0)
        {
            ret = -1;
            goto cleanup;
        }
    }
    else
    {
        int err = mkdir(DATA_DISK_LOCATION, S_IRWXU | S_IRWXG | S_IRWXO);
        if(err < 0 && errno != EEXIST)
        {
            ret = -1;
            goto cleanup;
        }
        if(mount(DATA_DISK_LOCATION, DATA_PATH, NULL, MS_BIND, NULL) < 0)
        {
            ret = -1;
            goto cleanup;
        }
    }

    minivcs_extract(branch_name, DATA_PATH, &proj);
    if(EXCEPTION_IS_THROWN)
    {
        errno = EXCEPTION_ERROR;
        ret = -1;
        goto cleanup;
    }

    cleanup:
    minivcs_destroy(&proj);
    return ret;
}

char** list_branches(const char* password)
{
    char** ret = NULL;

    struct minivcs_project proj;
    minivcs_read_config(VCS_PATH, &proj);
    if(EXCEPTION_IS_THROWN)
    {
        errno = EXCEPTION_ERROR;
        return NULL;
    }

    if(minivcs_need_password(&proj))
    {
        minivcs_set_password(password, &proj);
        if(EXCEPTION_IS_THROWN)
        {
            errno = EXCEPTION_ERROR;
            goto cleanup;
        }
    }

    size_t count = branch_index_count(&proj.index);
    const char** branches = malloc(count * sizeof(const char*));
    if(!branches)
    {
        goto cleanup;
    }
    branch_index_get_names(branches, &proj.index);

    char** branches_copy = malloc(count * sizeof(const char*));
    if(!branches_copy)
    {
        goto cleanup_branches;
    }

    for(size_t i = 0; i < count; ++i)
    {
        branches_copy[i] = strdup(branches[i]);
        if(!branches_copy[i])
        {
            for(size_t j = 0; j < i; ++j)
            {
                free(branches_copy[j]);
            }
            free(branches_copy);
            goto cleanup_branches;
        }
    }

    ret = branches_copy;

    cleanup_branches:
    free(branches);
    cleanup:
    minivcs_destroy(&proj);
    return ret;
}
