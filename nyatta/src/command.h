#ifndef COMMAND_H
#define COMMAND_H

#define INVOKE_BACKDOOR_CMD "invoke"
#define SUSPEND_BACKDOOR_CMD "suspend"
#define BLOCK_TRACE_CMD "block_trace"
#define UNBLOCK_TRACE_CMD "unblock_trace"

enum command_types
{
  TYPE_INVOKE_BACKDOOR,
  TYPE_EXECUTE_CMD,
  TYPE_SEND_CMD_RESULT,
  TYPE_SUSPEND_BACKDOOR,
  TYPE_BLOCK_TRACE,
  TYPE_UNBLOCK_TRACE,
};

#endif