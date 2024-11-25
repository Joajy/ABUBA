package com.hexagon.abuba.global.openfeign;

import com.hexagon.abuba.common.DataResponse;
import com.hexagon.abuba.global.openfeign.dto.request.*;
import com.hexagon.abuba.global.openfeign.dto.response.*;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.Mapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.Optional;

@FeignClient(name = "FinAPI", url = "")
public interface FinAPIClient {

    @PostMapping("/member")
    SignupResponseDTO signup(@RequestBody SignupRequestDTO signupRequestDTO);

    @PostMapping("/edu/demandDeposit/inquireDemandDepositAccountBalance")
    BalanceResponseDTO getBalance(@RequestBody BalanceRequestDTO balanceRequestDTO);

    @PostMapping(value = "/edu/accountAuth/openAccountAuth")
    Optional<OneTransferResponseDTO> accountAuth(@RequestBody OneTransferRequestDTO oneTransferRequestDTO);

    @PostMapping(value = "edu/demandDeposit/updateDemandDepositAccountWithdrawal")
    DepositResponseDTO withdrawDeposit(@RequestBody DepositRequestDTO depositRequestDTO);

    @PostMapping(value = "edu/demandDeposit/updateDemandDepositAccountDeposit")
    DepositResponseDTO addDeposit(@RequestBody DepositRequestDTO depositRequestDTO);

    @PostMapping(value = "edu/demandDeposit/inquireTransactionHistory")
    InQuireTransactionHistoryResponseDTO inquireTransactionHistory(@RequestBody InQuireTransactionHistoryRequestDTO inQuireTransactionHistoryRequestDTO);

    @PostMapping(value="edu/accountAuth/checkAuthCode")
    CheckAuthCodeResponseDTO checkAuthCode(@RequestBody CheckAuthCodeRequestDTO checkAuthCodeRequestDTO);

    @PostMapping(value="edu/demandDeposit/inquireTransactionHistoryList")
    HistoryResponseDTO getHistory(@RequestBody HistoryRequestDTO historyRequestDTO);

    @PostMapping(value="edu/demandDeposit/updateDemandDepositAccountTransfer")
    TransferResponseDTO transferDeposit(@RequestBody TransferRequestDTO transferRequestDTO);
}
