package com.hexagon.abuba.alarm.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.hexagon.abuba.alarm.AlarmResponseDTO;
import com.hexagon.abuba.alarm.entity.Alarm;
import com.hexagon.abuba.alarm.repository.AlarmRepository;
import com.hexagon.abuba.diary.entity.Diary;
import com.hexagon.abuba.user.Parent;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class AlarmService {
    private final AlarmRepository alarmRepository;
    private final Map<String, SseEmitter> sseEmitters = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;

    @Autowired
    public AlarmService(AlarmRepository alarmRepository, ObjectMapper objectMapper) {
        this.alarmRepository = alarmRepository;
        this.objectMapper = objectMapper;
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
    }
    public SseEmitter subscribe(String username) {
        SseEmitter oldEmitter = sseEmitters.get(username);
        if (oldEmitter != null) {
            oldEmitter.complete();
            sseEmitters.remove(username);//이전 Emitter 제거
        }
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);  // 새로운 Emitter 생성
        sseEmitters.put(username, emitter); //concurrentHashMap에 넣음
        // Emitter의 종료 시점 처리
        emitter.onCompletion(() -> {
            log.info("SSE Connection Completed for user: {}", username);
            sseEmitters.remove(username);  // 종료 시 Emitter 제거
        });
        emitter.onTimeout(() -> {
            log.info("SSE Connection Timeout for user: {}", username);
            sseEmitters.remove(username);  // 타임아웃 시 Emitter 제거
        });
        emitter.onError((e) -> {
            log.error("SSE Connection Error for user: {}", username, e);
            sseEmitters.remove(username);  // 오류 시 Emitter 제거
        });
        try {
            emitter.send(SseEmitter.event().name("connect").data("Connected"));
        } catch (IOException e) {
            log.error("Error sending initial connection event to user: {}", username, e);
            sseEmitters.remove(username);
        }
        return emitter;
    }

    @Scheduled(fixedRate = 30000) // 30초마다 실행
    public void sendHeartbeat() {
        sseEmitters.forEach((username, emitter) -> {
            try {
                log.info("Sending heartbeat for username: {}", username);
                emitter.send(SseEmitter.event().name("heartbeat").data("ping"));
            } catch (IOException e) {
                log.warn("Failed to send heartbeat to user: {}. Removing emitter.", username);
                sseEmitters.remove(username);
            }
        });
    }

    @Async
    public void sendNotification(Parent parent) {
        String username = parent.getUsername();
        SseEmitter emitter = sseEmitters.get(username);
        log.info("Trying to send notification for user: {}", username);
        if (emitter != null) {
            try {
                List<AlarmResponseDTO> response = new ArrayList<>();
                log.info("response.size()={}", response.size());
                String jsonData = objectMapper.writeValueAsString(response);
                emitter.send(SseEmitter.event().name("notification").data(jsonData));
                log.info("Notification sent successfully to user: {}", username);
            } catch (JsonProcessingException e) {
                log.error("JSON processing error for user: {}", username, e);
            } catch (IOException e) {
                log.warn("Failed to send notification to user: {}. Removing emitter.", username);
                sseEmitters.remove(username);
            } catch (Exception e) {
                log.error("Unexpected error while sending notification to user: {}", username, e);
                sseEmitters.remove(username);
            }
        } else {
            log.warn("No active emitter found for user: {}", username);
        }
    }

    public List<AlarmResponseDTO> getAlarms(Long parentId) {
        List<AlarmResponseDTO> response = new ArrayList<>();
        log.info("response.size()={}", response.size());
        Pageable pageable = PageRequest.of(0, 10); // 첫 번째 페이지에서 최대 10개 결과
        for (Alarm alarm : alarmRepository.findAllByParentId(parentId, pageable)) {
            Diary diary = alarm.getDiary();
            AlarmResponseDTO row = new AlarmResponseDTO(
                    diary.getCreatedAt(),
                    alarm.getIsRead(),
                    diary.getId(),
                    diary.getParent().getName(),
                    diary.getTitle()
            );
            response.add(row);
        }
        return response;
    }
}