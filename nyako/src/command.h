#ifndef COMMAND_H
#define COMMAND_H

enum command_types
{
  TYPE_INVOKE_BACKDOOR,
  TYPE_EXECUTE_CMD,
  TYPE_SUSPEND_BACKDOOR,
  TYPE_START_TRANSFER,
  TYPE_END_TRANSFER,
  TYPE_ADD_WATCHER,
  TYPE_REMOVE_WATCHER,
};

#endif