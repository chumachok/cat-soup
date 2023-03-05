# overview
cat soup is a rootkit developed to explore offensive capabilities using eBPF, its name was inspired by an animated film based on the manga created by Nekojiru. the rootkit consists of two components:
1. server (nyako)
2. client (nyatta)

for the details see documents/design.pdf and documents/manual.pdf.

## execution details

https://user-images.githubusercontent.com/54345367/222991260-15bb8d13-7aaa-4ab4-b15b-8a9c720d5242.mp4

## remote command execution

https://user-images.githubusercontent.com/54345367/222991652-827c742f-4c79-43bb-a440-eb34e5e37ffa.mp4

## process hiding

https://user-images.githubusercontent.com/54345367/222991368-baf0852f-7675-4632-b99d-d8dd90d36014.mp4

## diagrams
### state diagram of nyako
![state diagram of nyako](documents/diagrams/state_diagram_server.png)

### state diagram of nyatta
![state diagram of nyatta](documents/diagrams/state_diagram_client.png)
