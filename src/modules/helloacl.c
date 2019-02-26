/* ACL API example - An example of performing custom password authentication
 *
 * -----------------------------------------------------------------------------
 *
 * Copyright (c) 2019, Amazon Web Services, Inc.
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

// A simple global user
static RedisModuleUser *global;

/* Check that the password is "password" for any user */
RedisModuleUser *HelloACL_CheckPassword(void *user, size_t userlen, void *pass, size_t passlen) {
    REDISMODULE_NOT_USED(user);
    REDISMODULE_NOT_USED(userlen);
    REDISMODULE_NOT_USED(passlen);

    if(!strcmp(pass, "password")){
        return global;
    }
    return NULL;
}

/* HELLOACL.RESET */
int ResetCommand_RedisCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);

    RedisModule_FreeUser(global);
    global = RedisModule_CreateUser("global");
    RedisModule_SetUserACL(global, "allcommands");
    RedisModule_SetUserACL(global, "allkeys");
    RedisModule_SetUserACL(global, "on");

    return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

/* This function must be present on each Redis module. It is used in order to
 * register the commands into the Redis server. */
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    REDISMODULE_NOT_USED(argv);
    REDISMODULE_NOT_USED(argc);

    if (RedisModule_Init(ctx,"helloacl",1,REDISMODULE_APIVER_1)
        == REDISMODULE_ERR) return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx,"helloacl.reset",
        ResetCommand_RedisCommand,"readonly",0,0,0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    global = RedisModule_CreateUser("global");
    RedisModule_SetUserACL(global, "allcommands");
    RedisModule_SetUserACL(global, "allkeys");
    RedisModule_SetUserACL(global, "on");

    if (RedisModule_CreatePasswordAuthenticator("checkRoot", HelloACL_CheckPassword)
        == REDISMODULE_ERR) return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
