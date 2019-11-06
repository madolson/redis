/* ACL API example - An example of performing custom password authentication
 *
 * -----------------------------------------------------------------------------
 *
 * Copyright 2019 Amazon.com, Inc. or its affiliates.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define REDISMODULE_EXPERIMENTAL_API
#include "../redismodule.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <unistd.h>

// A simple global user
static RedisModuleUser *global;

/* HELLOACL.RESET */
int ResetCommand_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);

    RedisModule_FreeModuleUser(global);
    global = RedisModule_CreateModuleUser("global");
    RedisModule_SetModuleUserACL(global, "allcommands");
    RedisModule_SetModuleUserACL(global, "allkeys");
    RedisModule_SetModuleUserACL(global, "on");

    return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

/* HELLOACL.AUTHGLOBAL */
int AuthGlobalCommand_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);

    RedisModule_AuthenticateClientWithUser(ctx, global);

    return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

#define TIMEOUT_TIME 1000

/* Reply callback for auth command HELLO.AUTHASYNC */
int HelloACL_Reply(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);
    size_t length;

    RedisModuleString *user_string = RedisModule_GetBlockedClientPrivateData(ctx);
    const char *name = RedisModule_StringPtrLen(user_string, &length);

    RedisModuleUser *user = RedisModule_GetACLUser(name, length);
    if (!user) {
        return RedisModule_ReplyWithError(ctx, "Invalid Username or password");    
    }

    RedisModule_AuthenticateClientWithUser(ctx, user);
    return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

/* Timeout callback for auth command HELLO.AUTHASYNC */
int HelloACL_Timeout(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);
    return RedisModule_ReplyWithSimpleString(ctx, "Request timedout");
}

/* Private data freeing data for HELLO.AUTHASYNC command. */
void HelloACL_FreeData(RedisModuleCtx *ctx, void *privdata) {
    REDISMODULE_NOT_USED(ctx);
    RedisModule_FreeString(NULL, privdata);
}

/* This thread is presumably doing some background work to authenticate
 * the client like calling some remote server. */
void *HelloACL_ThreadMain(void *args) {
    void **targs = args;
    RedisModuleBlockedClient *bc = targs[0];
    RedisModuleString *user = targs[1];
    RedisModule_Free(targs);

    RedisModule_UnblockClient(bc,user);
    return NULL;
}

/* HELLOACL.AUTHASYNC */
int AuthAsyncCommand_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 2) return RedisModule_WrongArity(ctx);

    pthread_t tid;
    RedisModuleBlockedClient *bc = RedisModule_BlockClient(ctx, HelloACL_Reply, HelloACL_Timeout, HelloACL_FreeData, TIMEOUT_TIME);
    

    void **targs = RedisModule_Alloc(sizeof(void*)*2);
    targs[0] = bc;
    targs[1] = RedisModule_CreateStringFromString(NULL, argv[1]);

    if (pthread_create(&tid,NULL,HelloACL_ThreadMain,targs) != 0) {
        RedisModule_AbortBlock(bc);
        return RedisModule_ReplyWithError(ctx,"-ERR Can't start thread");
    }

    return REDISMODULE_OK;
}

/* This function must be present on each Redis module. It is used in order to
 * register the commands into the Redis server. */
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);

    if (RedisModule_Init(ctx,"helloacl",1,REDISMODULE_APIVER_1)
        == REDISMODULE_ERR) return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx,"helloacl.reset",
        ResetCommand_RedisCommand,"",0,0,0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx,"helloacl.authasync",
        AuthAsyncCommand_RedisCommand,"no-auth",0,0,0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx,"helloacl.authglobal",
        AuthGlobalCommand_RedisCommand,"no-auth",0,0,0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    global = RedisModule_CreateModuleUser("global");
    RedisModule_SetModuleUserACL(global, "allcommands");
    RedisModule_SetModuleUserACL(global, "allkeys");
    RedisModule_SetModuleUserACL(global, "on");

    return REDISMODULE_OK;
}
