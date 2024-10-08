package com.hexagon.abuba.alarm.controller;

import com.hexagon.abuba.alarm.service.AlarmService;
import com.hexagon.abuba.user.Parent;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@Slf4j
@RequestMapping("/api/v1/alarm")
public class AlarmController {

    private final AlarmService alarmService;
    // 사용자별 SSE 연결을 관리하기 위한 맵

    public AlarmController(AlarmService alarmService) {
        this.alarmService = alarmService;
    }

    //1. 연결 설정
    //2. 알림 전송 - 새로운 게시글이 등록됐음을 알리는 api 새로운글이 몇개 등록 되었는지 확인한다.
    //3. 알림 조회 - 알림 목록을 전달한다. 전달할 데이터는 게시글의 제목, 작성일, id, 게시글별 조회 여부
    // SSE 연결 설정
    @SecurityRequirement(name = "access")  // 이 API는 토큰이 필요함
    @Operation(summary = "알람 구독")
    @GetMapping(value = "/subscribe", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter subscribe(@AuthenticationPrincipal(expression = "user") Parent user) {
        log.info(" subscribe요청이 들어왔습니다. user={}",user.getId());
        return alarmService.subscribe(user.getUsername());
    }



//    // SSE 연결 설정
//    @GetMapping(value = "/subscribe/{userId}", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
//    public SseEmitter subscribe(@PathVariable String userId) {
//        SseEmitter emitter = new SseEmitter(60 * 1000L); // 1분 타임아웃
//        sseEmitters.put(userId, emitter);
//        emitter.onCompletion(() -> sseEmitters.remove(userId));
//        emitter.onTimeout(() -> sseEmitters.remove(userId));
//        return emitter;
//    }
//
//    // 특정 사용자들에게 알림을 보내는 메서드
//    @PostMapping("/send/{userId}")
//    public String sendNotificationToUser(@PathVariable String userId, @RequestParam String message) {
//        SseEmitter emitter = sseEmitters.get(userId);
//        if (emitter != null) {
//            try {
//                emitter.send(SseEmitter.event().name("notification").data(message));
//            } catch (IOException e) {
//                sseEmitters.remove(userId);
//                return "Failed to send notification";
//            }
//        }
//        return "Notification sent to user " + userId;
//    }
}

