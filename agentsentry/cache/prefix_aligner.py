from typing import List, Dict, Any

class PromptPrefixAligner:
    @staticmethod
    def align_messages(messages: List[Dict[str, Any]], tools_definition: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Structures message segments to anchor static context at the prefix of prompt payloads.
        Guarantees that the KV cache state remains stable for the prefix block across conversation turns.
        """
        if not messages:
            return []

        system_prompts: List[Dict[str, Any]] = []
        user_and_assistant: List[Dict[str, Any]] = []

        for msg in messages:
            # Normalize dictionary fields
            role = msg.get("role", "user")
            content = msg.get("content", "")
            
            cleaned_msg = {"role": role, "content": content}
            
            if role == "system":
                system_prompts.append(cleaned_msg)
            else:
                user_and_assistant.append(cleaned_msg)

        aligned: List[Dict[str, Any]] = []

        # 1. Anchor system prompts at the absolute beginning of the sequence
        for sys_msg in system_prompts:
            aligned.append(sys_msg)

        # 2. Inject tool descriptions as a system content segment if provided
        if tools_definition:
            tool_context = f"\n\n[System Tool-Use Schema]:\n{str(tools_definition)}\n"
            if aligned:
                # Merge with the first system prompt to avoid multi-system block splits
                aligned[0]["content"] = aligned[0]["content"] + tool_context
            else:
                aligned.append({"role": "system", "content": tool_context})

        # 3. Append remaining dynamic chat logs
        aligned.extend(user_and_assistant)

        return aligned
