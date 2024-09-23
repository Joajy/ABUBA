import React, { useState } from 'react';
import styled from 'styled-components';
import { Button } from '../../styles/styledComponents';

const SignupForm = () => {
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [authCode, setAuthCode] = useState('');
  const [timer, setTimer] = useState(60);
  const [isCodeSent, setIsCodeSent] = useState(false);
  const [isCodeVerified, setIsCodeVerified] = useState(false);
  const [error, setError] = useState('');

  const handleSendCode = () => {
    setIsCodeSent(true);
    const countdown = setInterval(() => {
      setTimer((prev) => {
        if (prev <= 1) {
          clearInterval(countdown);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  };

  const handleVerifyCode = () => {
    if (authCode === '123456') {
      setIsCodeVerified(true);
      alert('인증번호가 확인되었습니다!');
    } else {
      alert('인증번호가 올바르지 않습니다.');
    }
  };

  const handleSubmit = (e: { preventDefault: () => void; }) => {
    e.preventDefault();
  };

  return (
    <FormContainer onSubmit={handleSubmit}>
        <InputContainer>
        <FormGroup>
          <Input
            type="email"
            placeholder="이메일"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        <Button type="button" onClick={handleSendCode}>
            인증번호 전송
        </Button>
        </FormGroup>

          {isCodeSent && <span>{timer}</span>}
        <FormGroup>
          <Input
            type="text"
            placeholder="인증번호"
            value={authCode}
            onChange={(e) => setAuthCode(e.target.value)}
            required
          />
          <Button type="button" onClick={handleVerifyCode}>
            인증번호 확인
          </Button>
        </FormGroup>
          <Input
            type="text"
            placeholder="이름"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />

          <Input
            type="password"
            placeholder="비밀번호"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />


          <Input
            type="password"
            placeholder="비밀번호 확인"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />

        </InputContainer>

        {error && <ErrorMessage>{error}</ErrorMessage>}
        <Button type="submit">가입하기</Button>

    </FormContainer>
  );
};

export default SignupForm;

const FormContainer = styled.form`
  display: flex;
  flex-direction: column;
  width: 80%;
  padding: 20px;
  border-radius: 8px;
`;

const FormGroup = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
`;

const InputContainer = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  flex-direction: column;
  margin-bottom: 30px;
`;

const Input = styled.input`
  width: 80%;
  padding: 15px;
  border: 1px solid #ccc;
  border-radius: 8px;
`;

const ErrorMessage = styled.div`
  color: red;
  margin-bottom: 15px;
`;


