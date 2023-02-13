package main

import (
    "bufio"
    "fmt"
    "net"
    "strings"
)

func main() {
    // 开启服务端
    listener, err := net.Listen("tcp", "localhost:8080")
    if err != nil {
        fmt.Println("Error listening:", err.Error())
        return
    }
    defer listener.Close()
    fmt.Println("Listening on localhost:8080")

    for {
        // 等待客户端连接
        conn, err := listener.Accept()
        if err != nil {
            fmt.Println("Error accepting: ", err.Error())
            return
        }
        go handleRequest(conn)
    }
}

func handleRequest(conn net.Conn) {
    defer conn.Close()
    // 获取客户端请求
    request, err := bufio.NewReader(conn).ReadString('\n')
    if err != nil {
        fmt.Println("Error reading:", err.Error())
    }
    request = strings.TrimSpace(request)
	
    // 处理请求并返回响应
    response := processRequest(request)
    conn.Write([]byte(response + "\n"))
}

func processRequest(request string) string {
    // 在这里处理请求并返回响应
    return "Hello, " + request
}
