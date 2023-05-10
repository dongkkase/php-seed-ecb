<?php
require_once("seed.class.php");

class SeedECB extends Seed
{
    private $block          = 16;
    public  $pbUserKey      = '';
    private $paddingValue   = 0;
    private $pdwRoundKey    = array(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32);
    var $logview = false;

    public function __construct($_key)
    {
        //echo $this->ENC_KEY;
        $this->pbUserKey = $_key;
        // $this->logview = true;
    }

    public function encrypt($str)
    {
        $str = iconv("EUC-KR", "UTF-8", $str);

        $planBytes = array_slice(unpack('c*',$str), 0);
        if (count($planBytes) == 0) {
            return $str;
        }

        $paddingResult = null;
        for ($i=0; $i < count($planBytes); $i++)
        {
            $paddingResult .= $planBytes[$i];
        }

        $this->SeedRoundKey($this->pdwRoundKey, array_slice(unpack('c*',$this->pbUserKey), 0)); // 라운드키 생성

        $inDataBuffer = $this->addPadding($planBytes,$this->block);

        $encryptBytes = null;
        $rt = count($inDataBuffer) / $this->block;

        for ($i=0; $i < $rt; $i++)
        {
            $sSource = null;
            $sTarget = null;

            $this->arraycopy($inDataBuffer, ($i * $this->block) , $sSource, 0, $this->block);
            $this->SeedEncrypt($sSource, $this->pdwRoundKey, $sTarget); // 암호블록을 SEED로 암호화
            $this->arraycopy($sTarget, 0, $encryptBytes,($i * $this->block),count($sTarget));
        }

        return base64_encode(call_user_func_array("pack", array_merge(array("c*"), $encryptBytes)));

    }

    public function decrypt($str)
    {
        $str = iconv("EUC-KR", "UTF-8", $str);
        $str =  base64_decode($str);

        $planBytes = array_slice(unpack('c*',$str), 0); // 평문을 바이트 배열로 변환
        if (count($planBytes) == 0)
        {
            return $str;
        }

        $this->SeedRoundKey($this->pdwRoundKey, array_slice(unpack('c*',$this->pbUserKey), 0)); // 라운드키 생성

        $rt = count($planBytes) / $this->block;
        $sSource = null;
        $sTarget = null;
        $decryptBytes = null;

        for ($i=0; $i < $rt; $i++)
        {
            $this->arraycopy($planBytes, ($i * $this->block) , $sSource, 0, $this->block);
            $this->SeedDecrypt($sSource, $this->pdwRoundKey, $sTarget); // 암호블록을 SEED로 복호화
            $this->arraycopy($sTarget, 0, $decryptBytes,($i * $this->block),$this->block);
        }


        $decryptBytesPadding = $this->removePadding($decryptBytes,$this->block);

        $decryptBytesPaddingResult = null;
        for ($i=0; $i < count($decryptBytesPadding); $i++)
        {
              $decryptBytesPaddingResult .= chr($this->convertMinus128($decryptBytesPadding[$i]));
        }

        return $decryptBytesPaddingResult;

    }

    /**
    * Java의 arraycopy 함수를 php로 구현
    * 원본 배열의 해당 위치부터 시작한 값을 복사할 배열의 위치에 정해진 길이만큼 대치시켜준후, 복사할 배열을 반환
    *
    * @param array $src Source array.
    * @param integer $srcPos Start position of source array.
    * @param array $dest Destination array.
    * @param integer $destPos Start position of destination array.
    * @param integer $length Integer to count the arrays of..
    *
    * @return array Return destination source array.
    */
    public function arraycopy($src, $srcPos, &$dest, $destPos, $length)
    {
        for ($i=$srcPos; $i < $srcPos+$length; $i++)
        {
            $dest[$destPos] = $src[$i];
            $destPos++;
        }
    }


    /**
    * Bytes값을 Minus 128 표현식으로 변환
    * 32bit에서 Bytes객체의 8번째 자리수가 1인 경우 음수로 표기
    * 64bit에서 양수로 표현되기 때문에 정수를 강제로 32bit로 인식하게해 오버플로우 시켜 음수로 표기되도록 변환 시켜줌
    *
    * @param mixed[] $bytes Array of bytes or continuous string of hex.
    *
    * @return array List of hex lists or string of hex.
    */
    private function convertMinus128($bytes)
    {
        // 64비트가 아닌 경우 그대로 출력
        if (PHP_INT_SIZE > 4)
        {
            return $bytes;
        }

        if (is_array($bytes))
        {
            $ret = array();
            
            foreach ($bytes as $val)
            {
                $ret[] = (($val+128) % 256) -128;
            }
            
            return $ret;
        }

        return (($bytes+128) % 256) -128;
    }

    /**
    * 요청한 Block Size를 맞추기 위해 Padding을 추가한다.
    *
    * @param source byte[] 패딩을 추가할 bytes
    * @param blockSize int block size
    * @return byte[] 패딩이 추가 된 결과 bytes
    */
    public function addPadding($planBytes, $block)
    {
        $paddingResult = array();
        $paddingCnt = count($planBytes) % $block;
        $addPaddingCnt = $block - $paddingCnt;

        if ($paddingCnt != 0)
        {
            $this->arraycopy($planBytes, 0, $paddingResult, 0, count($planBytes));

            for ($i=0; $i < $addPaddingCnt; $i++)
            {
                $paddingResult[count($planBytes)+$i] = $this->paddingValue;
            }

            $paddingResult[count($paddingResult) - 1] = $addPaddingCnt;

            return $paddingResult;
        }
        else
        {
            return $planBytes;
        }
    }

    /**
    * 요청한 Block Size를 맞추기 위해 추가 된 Padding을 제거한다.
    *
    * @param source byte[] 패딩을 제거할 bytes
    * @param blockSize int block size
    * @return byte[] 패딩이 제거 된 결과 bytes
    */
    public function removePadding($planBytes, $block)
    {
        $paddingResult = array();
        $isPadding = FALSE;

        $lastValue = $planBytes[count($planBytes)-1];

        if ($lastValue <= ($block -1))
        {
            $zeroPaddingCount = $lastValue -1;
            for ($i=2; $i < ($zeroPaddingCount+2); $i++)
            {
                if ($planBytes[count($planBytes)-1] != $this->paddingValue)
                {
                    $isPadding = FALSE;
                    break;
                }
            }
            $isPadding = TRUE;

        }
        else
        {

            $isPadding = FALSE;

        }


        if ($isPadding)
        {
            $paddingResultCount = count($planBytes) - $lastValue;
            $this->arraycopy($planBytes, 0, $paddingResult, 0, $paddingResultCount);
        }
        else
        {

            $paddingResult = $planBytes;
        }


        return $paddingResult;

    }

    function logview($_flag)
    {
        $this->logview = $_flag;
    }

    function log($string, $title='')
    {
        if ($this->logview)
        {
            if ($title)
            {
                echo "<div style='display:inline-block;margin-top:15px;font-weight:bold;font-size:12px;background-color: rgb(255,255,255);'>";
                echo $title;
                echo "</div>";
            }
            echo "<pre style='margin:-10px 10px 10px 10px;padding:10px;border:1px solid #ccc;border-radius:5px;background:#fff'>";
            print_r(var_dump($string));
            echo "</pre>";
        }
    }

}
