# cat soup

## overview
cat soup is a kernel-level covert channel rootkit developed to explore offensive capabilities using eBPF, its name was inspired by an animated film based on the manga created by Nekojiru. the rootkit consists of two components:
1. nyako (server)
2. nyatta (client)

the encrypted messages between the components are exchanged via a covert channel that utilizes an If-None-Match HTTP header. header example:

```
If-None-Match:
lo7ct.0.0.24.nwlrbbmqbhcdarzowkkyhid.nwlrbbmqbhcdarzowkkyhid.dqscdxrjmowfrx
sjybldbefsarcbynecdyggxxpklorellnmpapqfwkhopkmcoqhnwnkuewhsqmgbbuqcljjivswm
dkqtbxixmvtrrbljptnsnfwzqfjmafadrrwsofsbcnuvqhffbsaqxwpqcacehchzvfrkmlnozjk
pqpxrjxkitzyxacbhhkicqcoendtomfgdwdwfcgpxiqvkuytdlcgdewhtaciohordtqkvwcsgsp
qoqmsboaguwnnyqxnzlgdgwpbtrwblnsadeuguumoqcdrubetokyxhoachwdvmxxrdryxlmndqt
ukwagmlejuukwcibxubumenmeyatdrmydiajxloghiqfmzhlvihjouvsuyoypayulyeimuotehz
riicfskpggkbbipzzrzucxamludfykgruowzgiooobppleqlwphapjnadqhdc
```

remote command execution can be performed by entering a linux command. rootkit specific commands are outlined in the table below.

| command       | technical details                                       | description                           |
| ------------- | ------------------------------------------------------- | ------------------------------------  |
| invoke        | send a message with the command type TYPE_INVOKE        | invokes nyako to process commands     |
| suspend       | send a message with the command type TYPE_SUSPEND       | suspends nyako making it unresponsive |
| block_trace   | send a message with the command type TYPE_BLOCK_TRACE   | blocks any tracing attepts            |
| unblock_trace | send a message with the command type TYPE_UNBLOCK_TRACE | disables tracing blocking             |
| terminate     | send a message with the command type TYPE_TERMINATE     | terminates nyako                      |

for the additional details see documents/design.pdf and documents/manual.pdf.

## execution details

https://user-images.githubusercontent.com/54345367/222991260-15bb8d13-7aaa-4ab4-b15b-8a9c720d5242.mp4

## remote command execution

https://user-images.githubusercontent.com/54345367/222991652-827c742f-4c79-43bb-a440-eb34e5e37ffa.mp4

## process hiding
inspired by https://github.com/pathtofile/bad-bpf#pid-hide

https://user-images.githubusercontent.com/54345367/222991368-baf0852f-7675-4632-b99d-d8dd90d36014.mp4

## diagrams
### state diagram of nyako
![state diagram of nyako](documents/diagrams/state_diagram_server.png)

### state diagram of nyatta
![state diagram of nyatta](documents/diagrams/state_diagram_client.png)
