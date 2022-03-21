#ifndef COMMAND_H
#define COMMAND_H

#define INVOKE_CMD "invoke"
#define SUSPEND_CMD "suspend"
#define BLOCK_TRACE_CMD "block_trace"
#define UNBLOCK_TRACE_CMD "unblock_trace"
#define TERMINATE_CMD "terminate"

enum command_types
{
  TYPE_INVOKE,
  TYPE_EXECUTE_CMD,
  TYPE_SEND_CMD_RESULT,
  TYPE_SUSPEND,
  TYPE_BLOCK_TRACE,
  TYPE_UNBLOCK_TRACE,
  TYPE_TERMINATE,
};

#endif