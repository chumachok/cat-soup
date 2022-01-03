#ifndef COMMAND_H
#define COMMAND_H

#define ADD_WATCHER_CMD "add_watcher"
#define REM_WATCHER_CMD "remove_watcher"

enum command_types
{
  TYPE_INVOKE_BACKDOOR,
  TYPE_SUSPEND_BACKDOOR,
  TYPE_START_TRANSFER,
  TYPE_END_TRANSFER,
  TYPE_ADD_WATCHER,
  TYPE_REMOVE_WATCHER,
};

#endif