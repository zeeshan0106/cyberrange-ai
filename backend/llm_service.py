import time
import json
import logging
import asyncio
from typing import Tuple, Optional, Any, Type
from pydantic import BaseModel, ValidationError
from litellm import acompletion

try:
    from backend.config import settings
except ImportError:
    from config import settings

logger = logging.getLogger("cyberrange.llm")


def sanitize_llm_error(e: Exception) -> str:
    """
    Categorizes LLM provider exceptions into concise, safe messages
    without leaking API keys or internal data.
    """
    if isinstance(e, asyncio.TimeoutError):
        return "Network request timed out"

    err_name = type(e).__name__.lower()
    err_msg = str(e).lower()

    # 1. Authentication / API key failures
    if (
        "auth" in err_name
        or "auth" in err_msg
        or "unauthorized" in err_msg
        or "api key" in err_msg
        or "api_key" in err_msg
        or "401" in err_msg
        or "403" in err_msg
    ):
        return "Authentication failed: invalid or unauthorized API key"

    # 2. Rate limit / Quota failures
    if (
        "ratelimit" in err_name
        or "rate_limit" in err_msg
        or "rate limit" in err_msg
        or "quota" in err_msg
        or "429" in err_msg
        or "budget" in err_name
    ):
        return "Rate limit or quota exceeded"

    # 3. Invalid model name / Model not found / Unsupported model
    if (
        "notfound" in err_name
        or "badrequest" in err_name
        or "invalidrequest" in err_name
        or ("model" in err_msg and ("not found" in err_msg or "does not exist" in err_msg or "invalid" in err_msg or "unsupported" in err_msg))
    ):
        return "Invalid model name or model not found"

    # 4. Timeout / Connection / Network failures
    if (
        "timeout" in err_name
        or "timeout" in err_msg
        or "connection" in err_name
        or "connection" in err_msg
        or "serviceunavailable" in err_name
    ):
        return "Network request timed out or connection failed"

    # 5. Default generic sanitized error
    return f"LLM provider error: {type(e).__name__}"


async def execute_llm_with_validation(
    prompt: str,
    validation_model: Type[BaseModel]
) -> Tuple[Optional[BaseModel], Optional[str]]:
    """
    Executes an LLM call via the configured provider with retry and output validation.
    The API key and model name are passed explicitly to prevent cross-provider key leakage.
    
    Returns:
        (validated_pydantic_instance, fallback_reason)
        If validated_pydantic_instance is not None, fallback_reason is None.
        If validated_pydantic_instance is None, fallback_reason is one of:
            "no_api_key", "timeout", "llm_error", "invalid_output"
    """
    api_key = settings.LLM_API_KEY
    if not api_key:
        logger.warning("LLM call skipped: no API key configured. Using fallback generation.")
        return None, "no_api_key"

    max_attempts = 1 + max(0, settings.LLM_MAX_RETRIES)
    last_reason = "llm_error"

    for attempt in range(1, max_attempts + 1):
        start_time = time.perf_counter()
        try:
            logger.info("Executing LLM call [model=%s, attempt=%d/%d, timeout=%.1fs]",
                        settings.LLM_MODEL, attempt, max_attempts, settings.LLM_TIMEOUT)
            
            response = await asyncio.wait_for(
                acompletion(
                    model=settings.LLM_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    api_key=api_key
                ),
                timeout=settings.LLM_TIMEOUT
            )
            
            latency_ms = (time.perf_counter() - start_time) * 1000
            content = response.choices[0].message.content
            
            if not content:
                logger.warning("LLM returned empty response [model=%s, latency=%.2fms, attempt=%d/%d]",
                               settings.LLM_MODEL, latency_ms, attempt, max_attempts)
                last_reason = "invalid_output"
                continue

            # Attempt to parse as JSON
            parsed_data = None
            try:
                stripped = content.strip()
                if stripped.startswith("{") and stripped.endswith("}"):
                    parsed_data = json.loads(stripped)
                else:
                    import re
                    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
                    if match:
                        parsed_data = json.loads(match.group(1))
                    else:
                        parsed_data = json.loads(stripped)
            except Exception as json_err:
                logger.warning("LLM response is not valid JSON [model=%s, latency=%.2fms, attempt=%d/%d]: %s",
                               settings.LLM_MODEL, latency_ms, attempt, max_attempts, str(json_err))
                last_reason = "invalid_output"
                continue

            # Validate against expected Pydantic schema
            try:
                validated = validation_model.model_validate(parsed_data)
                logger.info("LLM call succeeded [model=%s, latency=%.2fms, attempt=%d/%d]",
                            settings.LLM_MODEL, latency_ms, attempt, max_attempts)
                return validated, None
            except ValidationError as val_err:
                logger.warning("LLM output failed schema validation [model=%s, latency=%.2fms, attempt=%d/%d]: %s",
                               settings.LLM_MODEL, latency_ms, attempt, max_attempts, str(val_err))
                last_reason = "invalid_output"
                continue

        except asyncio.TimeoutError:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.warning("LLM call timed out [model=%s, timeout=%.1fs, latency=%.2fms, attempt=%d/%d]",
                           settings.LLM_MODEL, settings.LLM_TIMEOUT, latency_ms, attempt, max_attempts)
            last_reason = "timeout"
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            clean_err = sanitize_llm_error(e)
            logger.warning("LLM call failed [model=%s, latency=%.2fms, attempt=%d/%d]: %s",
                           settings.LLM_MODEL, latency_ms, attempt, max_attempts, clean_err)
            last_reason = "llm_error"
            # Fast fail on non-recoverable errors (auth failure, invalid model, etc.)
            if "Authentication failed" in clean_err or "Invalid model name" in clean_err:
                break

    logger.warning("All LLM attempts exhausted. Activating fallback generator [reason=%s]", last_reason)
    return None, last_reason
