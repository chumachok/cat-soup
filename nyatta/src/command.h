#ifndef COMMAND_H
#define COMMAND_H

#define INVOKE_BACKDOOR_CMD "invoke"
#define SUSPEND_BACKDOOR_CMD "suspend"

enum command_types
{
  TYPE_INVOKE_BACKDOOR,
  TYPE_EXECUTE_CMD,
  TYPE_SEND_CMD_RESULT,
  TYPE_SUSPEND_BACKDOOR,
};

#endif